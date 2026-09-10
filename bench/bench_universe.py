"""Universe bakeoff: every installed grep vs rg reference. Differential oracle
(match sets must equal rg's) + median wall time. N/A entries carry reasons."""
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent
NK = HERE.parent / "target" / "release" / "nkgrep"
CORPUS = HERE / "corpus"
CORPUS_GIT = HERE / "corpus-git"
CORPUS_TGREP = HERE / "corpus-tgrep"
IDX = HERE / "nk.idx.json"
RUNS = 3
ENV = dict(os.environ, PATH=os.path.expanduser("~/.cargo/bin") + ":" + os.environ["PATH"])

QUERIES = [
    "TODO_FIXME_ALPHA",
    "needle_1|needle_2|needle_3",
    "fn parse_config",
    "config",
]


def run(cmd, cwd):
    t0 = time.perf_counter()
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=ENV)
    return p, (time.perf_counter() - t0) * 1000.0


def norm(path):
    return path.lstrip("./")


def parse_colon_file(out):
    """file:line:text lines -> set. Splits path/line from left, text keeps colons."""
    rows = set()
    for line in out.splitlines():
        if not line.strip():
            continue
        a, _, rest = line.partition(":")
        b, _, text = rest.partition(":")
        if not b.strip().isdigit():
            continue
        rows.add((norm(a), int(b), text))
    return rows


def rg_set(q):
    p, _ = run(["rg", "--json", "--", q, "."], CORPUS)
    assert p.returncode in (0, 1), p.stderr[:300]
    out = set()
    for line in p.stdout.splitlines():
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            continue
        if o.get("type") == "match":
            d = o["data"]
            out.add((norm(d["path"]["text"]), d["line_number"], d["lines"]["text"].rstrip("\n")))
    return out


def nk_json_set(cmd, cwd):
    p, _ = run(cmd, cwd)
    assert p.returncode in (0, 1), p.stderr[:300]
    out = set()
    for line in p.stdout.splitlines():
        if line.strip():
            o = json.loads(line)
            out.add((norm(o["path"]), o["line"], o["text"]))
    return out


def nk_set(q):
    return nk_json_set([str(NK), "--", q, "."], CORPUS)


def nk_idx_set(q):
    return nk_json_set([str(NK), "--use-index", str(IDX), "--", q, "corpus"], HERE)


TOOLS = {
    # name: (cwd, argv(q), set_parser, equivalent-work note)
    "rg": (CORPUS, lambda q: ["rg", "--json", "--", q, "."], lambda p: None),
    "nk": (CORPUS, lambda q: [str(NK), "--", q, "."], lambda p: None),
    "nk-idx": (HERE, lambda q: [str(NK), "--use-index", str(IDX), "--", q, "corpus"], lambda p: None),
    "bsd-grep": (HERE, lambda q: ["grep", "-rInE", "--exclude-dir=.git", "--", q, "corpus"], parse_colon_file),
    "git-grep": (CORPUS_GIT, lambda q: ["git", "grep", "-n", "-E", "--", q], parse_colon_file),
    "ugrep": (HERE, lambda q: ["ugrep", "-r", "-n", "--", q, "corpus"], parse_colon_file),
    "ag": (HERE, lambda q: ["ag", "--nogroup", "--nocolor", "--", q, "corpus"], parse_colon_file),
    "ack": (HERE, lambda q: ["ack", "--nogroup", "--nocolor", "--", q, "corpus"], parse_colon_file),
    "tgrep": (CORPUS_TGREP, lambda q: ["tgrep", "-n", "--", q, "."], parse_colon_file),
}

NA = {
    "ast-grep 0.45.3": "no supported language for .txt corpus (empty output)",
    "pt": "PATH pt is an unrelated Tcl tool (name collision)",
    "hypergrep": "Linux-only upstream",
    "sift/ucg": "not installed; upstream stale",
}


def setup_git_corpus():
    import shutil
    if CORPUS_GIT.exists():
        return
    shutil.copytree(CORPUS, CORPUS_GIT)
    env = dict(ENV, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
    for args in (["git", "init", "-q"], ["git", "add", "-A"], ["git", "commit", "-qm", "init"]):
        subprocess.run(args, cwd=CORPUS_GIT, env=env, check=True, capture_output=True)


class TgrepServe:
    def __enter__(self):
        self.p = subprocess.Popen(["tgrep", "serve", "."], cwd=CORPUS_TGREP,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV)
        for _ in range(120):
            p, _ = run(["tgrep", "status", "."], CORPUS_TGREP)
            if "complete" in p.stdout.lower():
                return self
            time.sleep(1)
        raise RuntimeError("tgrep serve never reported complete: " + p.stdout[:300])
        return self

    def __exit__(self, *a):
        self.p.terminate()
        try:
            self.p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.p.kill()


def tool_set(name, q):
    cwd, argv, parser = TOOLS[name]
    p, _ = run(argv(q), cwd)
    assert p.returncode in (0, 1), f"{name}: rc={p.returncode} {p.stderr[:200]}"
    if name == "rg":
        return rg_set(q)
    if name == "nk":
        return nk_set(q)
    if name == "nk-idx":
        rows = nk_idx_set(q)
        return {(r[0].split("/", 1)[1] if "/" in r[0] else r[0], r[1], r[2]) for r in rows}
    rows = parser(p.stdout)
    # strip corpus dir prefix for tools run from HERE against corpus/
    if name in ("bsd-grep", "ugrep", "ag", "ack"):
        rows = {(r[0].split("/", 1)[1] if "/" in r[0] else r[0], r[1], r[2]) for r in rows}
    return rows


def main():
    setup_git_corpus()
    ref = {}
    print(f"{'tool':10s} " + " ".join(f"{q[:14]:>14s}" for q in QUERIES) + "   oracle")
    results = {}
    with TgrepServe():
        for name in TOOLS:
            row, ok_all = [], True
            for q in QUERIES:
                if q not in ref:
                    ref[q] = rg_set(q)
                got = tool_set(name, q)
                ok = got == ref[q]
                ok_all = ok_all and ok
                if not ok:
                    row.append(f"DIVERGE({len(got - ref[q])}/{len(ref[q] - got)})")
                else:
                    cwd, argv, _ = TOOLS[name]
                    run(argv(q), cwd)
                    ts = [run(argv(q), cwd)[1] for _ in range(RUNS)]
                    row.append(f"{statistics.median(ts):.1f}ms")
            results[name] = ok_all
            print(f"{name:10s} " + " ".join(f"{c:>14s}" for c in row) + f"   {'EQUAL' if ok_all else 'DIVERGE'}")
    print("\nN/A (not comparable here):")
    for k, v in NA.items():
        print(f"  {k}: {v}")
    print("\nreference match counts:", {q[:12]: len(ref[q]) for q in QUERIES})


if __name__ == "__main__":
    main()
