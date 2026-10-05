"""Race nkg against the indexed and scan competitors, parity-gated.

Every tool gets the same corpus. A tool whose match set differs from
ripgrep's is dropped before it is ever timed, so a fast wrong answer can
never win a row. Host conditions print first, because a millisecond on a
loaded box is not a millisecond on a quiet one.

Tools that write their index inside the tree they search (tgrep, ugrep)
each get a pristine copy under a scratch dir, so a run does not depend on
whatever a previous run left behind.

    python3 bench/race.py                 # race whatever is installed
    python3 bench/race.py --rounds 21
"""
import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parent
NK = ROOT / "target" / "release" / "nkg"
CORPUS = HERE / "corpus"
NKG_IDX = HERE / "nk.idx.bin"
SCRATCH = Path(tempfile.gettempdir()) / "nkg-race"
QUERIES = [
    "TODO_FIXME_ALPHA",
    "needle_1|needle_2|needle_3",
    "fn parse_config",
    "config",
]


def run(cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def host_conditions():
    """Print what the timings depend on, so the numbers can be judged."""
    print("== host ==")
    try:
        load = os.getloadavg()[0]
    except OSError:
        load = float("nan")
    d = []
    for _ in range(10):
        t = time.perf_counter()
        time.sleep(0.1)
        d.append((time.perf_counter() - t) * 1000)
    jitter = max(d) - min(d)
    print(f"  cores {os.cpu_count()}   load {load:.2f}")
    print(f"  sleep(100ms) jitter {jitter:.3f} ms over 10 samples")
    if jitter > 2.0:
        print("  WARNING: jitter above 2 ms cannot resolve a 4 ms gap.")


def build_nkg():
    print("== build nkg ==")
    r = run(["cargo", "build", "--release"], cwd=ROOT)
    if r.returncode != 0 or not NK.exists():
        sys.exit(f"cargo build failed:\n{r.stderr[-2000:]}")
    print(f"  {NK} ok")


def build_corpus():
    if not CORPUS.exists() or not any(CORPUS.rglob("*.txt")):
        print("== generate corpus ==")
        r = run([sys.executable, str(HERE / "gen_corpus.py")], cwd=HERE)
        if r.returncode != 0:
            sys.exit(f"gen_corpus failed:\n{r.stdout[-800:]}{r.stderr[-800:]}")
    print(f"== corpus ==\n  {sum(1 for p in CORPUS.rglob('*') if p.is_file())} files")


def nkg_index():
    print("== nkg index ==")
    NKG_IDX.unlink(missing_ok=True)
    r = run([str(NK), "index", "corpus", "--index", NKG_IDX.name], cwd=HERE)
    if r.returncode != 0:
        sys.exit(f"nkg index failed: {r.stderr[-500:]}")
    print(f"  {NKG_IDX.stat().st_size:,} B")


def discover():
    """(name, exe, indexer) for each tool present on this host."""
    home = Path.home()
    # tgrep 1.0.x emits `path:text` with no line number and rejects
    # `--no-color`; 1.6.x has both. The harness targets 1.6.x.
    wanted = [
        ("nkg", "nkg", None),
        ("rg", "rg", None),
        ("ugrep", str(home / "ugrep-src/bin/ugrep"), str(home / "ugrep-src/bin/ugrep-indexer")),
        ("tgrep", str(home / "tgrep-src/target/release/tgrep"), "inplace"),
        ("zoekt", str(home / "go/bin/zoekt"), str(home / "go/bin/zoekt-index")),
    ]
    found = []
    for name, exe, indexer in wanted:
        if name == "nkg":
            found.append((name, str(NK), None))
            continue
        exe = shutil.which(exe) or (exe if Path(exe).exists() else None)
        if not exe:
            print(f"== skip {name} == not installed")
            continue
        if indexer not in (None, "inplace") and not Path(indexer).exists():
            print(f"== skip {name} == indexer missing at {indexer}")
            continue
        found.append((name, exe, indexer))
    return found


def prepare(tools):
    """Root each tool searches, and its index directory, in a clean scratch dir."""
    if SCRATCH.exists():
        shutil.rmtree(SCRATCH)
    SCRATCH.mkdir(parents=True)
    roots, idxdirs = {}, {}
    for name, exe, indexer in tools:
        if name in ("nkg", "rg"):
            roots[name] = CORPUS
            continue
        if name == "zoekt":
            d = SCRATCH / "zoekt-idx"
            d.mkdir()
            r = run([indexer, "-index", str(d), str(CORPUS)])
            if r.returncode != 0:
                sys.exit(f"zoekt index failed: {r.stderr[-400:]}")
            roots[name] = CORPUS
            idxdirs[name] = d
            continue
        # tgrep and ugrep index in place, so hand each a pristine copy.
        root = SCRATCH / name
        shutil.copytree(CORPUS, root)
        cmd = [exe, "index", str(root)] if indexer == "inplace" else [indexer, "-f", str(root)]
        r = run(cmd)
        if r.returncode != 0:
            print(f"== skip {name} == index failed: {r.stderr.strip()[-200:]}")
            continue
        roots[name] = root
    return roots, idxdirs


def build_argv(name, exe, q, roots, idxdirs):
    if name == "nkg":
        return [str(NK), "--use-index", str(NKG_IDX), "--", q, "corpus"]
    if name == "rg":
        return [exe, "--json", "--", q, "corpus"]
    if name == "ugrep":
        return [exe, "--index", "-r", "-n", q, str(roots[name])]
    if name == "tgrep":
        # `--no-color` is rejected by tgrep 1.0.x (exit 2, no output);
        # `--color never` is the portable spelling. `-n` is explicit because
        # 1.0.x prints `path:text` without it, and the parser needs the line.
        return [exe, "--color", "never", "-n", q, str(roots[name])]
    if name == "zoekt":
        return [exe, "-index_dir", str(idxdirs[name]), q]
    raise AssertionError(name)


def rel(name, path, roots):
    """Reduce every tool's output to a path relative to the corpus root.

    rg and nkg print `corpus/pkg_00/...`, zoekt prints `pkg_00/...`, and
    tgrep and ugrep print an absolute path into their own scratch copy.
    Strip whichever prefix the tool used; what follows is comparable.
    """
    root = roots.get(name)
    if root is not None:
        s = str(root).rstrip("/")
        if path.startswith(s + "/"):
            return path[len(s) + 1:]
    parts = path.replace("\\", "/").split("/")
    if "corpus" in parts:
        return "/".join(parts[parts.index("corpus") + 1:])
    return path.lstrip("./")


def match_set(name, exe, q, roots, idxdirs):
    """(path, line, text) triples, or None if the tool cannot answer."""
    p = run(build_argv(name, exe, q, roots, idxdirs), cwd=HERE)
    if p.returncode not in (0, 1):
        return None
    # Measured: tgrep writes matches to stdout, 146 lines, stderr empty. The
    # earlier stderr sighting came from a `2>&1` capture, not from tgrep.
    stream = p.stdout
    out = set()
    try:
        for line in stream.splitlines():
            if not line.strip():
                continue
            if name == "nkg":
                o = json.loads(line)
                out.add((rel(name, o["path"], roots), o["line"], o["text"]))
            elif name == "rg":
                ev = json.loads(line)
                if ev.get("type") != "match":
                    continue
                d = ev["data"]  # rg nests the payload under "data"
                out.add(
                    (
                        rel(name, d["path"]["text"], roots),
                        d["line_number"],
                        d["lines"]["text"].rstrip("\n"),
                    )
                )
            else:
                parts = line.split(":", 2)  # path:line:text
                if len(parts) == 3 and parts[1].isdigit():
                    # tgrep prints `./path:38: text` - drop the leading `./`
                    # and the space after the colon, so the text compares equal.
                    out.add(
                        (
                            rel(name, parts[0].removeprefix("./"), roots),
                            int(parts[1]),
                            parts[2].lstrip(),
                        )
                    )
    except (json.JSONDecodeError, KeyError, IndexError):
        return None
    return out


def index_sizes(roots, idxdirs):
    out = {}
    if NKG_IDX.exists():
        out["nkg"] = NKG_IDX.stat().st_size
    if "zoekt" in idxdirs:
        out["zoekt"] = sum(
            f.stat().st_size for f in idxdirs["zoekt"].rglob("*") if f.is_file()
        )
    for name in ("tgrep", "ugrep"):
        if name in roots:
            marks = [p for p in roots[name].rglob(".*") if p.is_file()]
            if marks:
                out[name] = sum(p.stat().st_size for p in marks)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=11)
    args = ap.parse_args()

    host_conditions()
    build_nkg()
    build_corpus()
    nkg_index()

    tools = discover()
    print(f"== tools ==\n  {', '.join(t[0] for t in tools)}")
    roots, idxdirs = prepare(tools)
    tools = [t for t in tools if t[0] in roots]
    print(f"== prepared ==\n  {', '.join(t[0] for t in tools)}")

    print("== parity gate (a tool that differs is dropped, never timed) ==")
    rg_exe = shutil.which("rg")
    survivors = []
    for name, exe, _ in tools:
        if name == "rg":
            survivors.append((name, exe, None))
            continue
        for q in QUERIES:
            ref = match_set("rg", rg_exe, q, roots, idxdirs)
            if match_set(name, exe, q, roots, idxdirs) != ref:
                print(f"  {name:8s} DIFFERS on {q!r} - dropped")
                break
        else:
            print(f"  {name:8s} matches ripgrep on all {len(QUERIES)} probes")
            survivors.append((name, exe, None))

    if "nkg" not in [n for n, _, _ in survivors]:
        sys.exit("nkg failed its own parity gate - refusing to publish")

    print(f"== timing ({args.rounds} interleaved rounds, median) ==")
    print(f"  {'query':28s} " + "  ".join(f"{n:>8s}" for n, _, _ in survivors))
    totals = {n: 0.0 for n, _, _ in survivors}
    wins = {n: 0 for n, _, _ in survivors}
    for q in QUERIES:
        samples = {n: [] for n, _, _ in survivors}
        for _ in range(args.rounds):
            for name, exe, _ in survivors:
                t0 = time.perf_counter()
                run(build_argv(name, exe, q, roots, idxdirs), cwd=HERE)
                samples[name].append((time.perf_counter() - t0) * 1000)
        meds = {n: statistics.median(v) for n, v in samples.items()}
        best = min(meds, key=meds.get)
        for n, v in meds.items():
            totals[n] += v
            wins[n] += n == best
        row = "  ".join(
            f"{meds[n]:7.1f}" + ("*" if n == best else " ") for n, _, _ in survivors
        )
        print(f"  {q:28s} {row}")
    print(f"  {'TOTAL':28s} " + "  ".join(f"{totals[n]:7.1f} " for n, _, _ in survivors))
    print(f"  {'fastest per query':28s} " + "  ".join(f"{wins[n]:8d}" for n, _, _ in survivors))

    sizes = index_sizes(roots, idxdirs)
    if sizes:
        print("== index size ==")
        for n, b in sizes.items():
            print(f"  {n:8s} {b:>12,} B")


if __name__ == "__main__":
    main()
