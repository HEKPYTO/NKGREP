"""Indexed bakeoff: scan-nk vs indexed-nk (full, equality) vs indexed top-k vs rg.
Index stores paths under root "corpus" from HERE, so indexed runs use cwd=HERE.
Kill gates: (A) indexed full sets equal rg sets. (B) selective indexed total
<= scan total. (C) top-k latency on concentrated query beats rg full."""
import json
import statistics
import subprocess
import time
from pathlib import Path

HERE = Path(__file__).parent
NK = HERE.parent / "target" / "release" / "nkg"
CORPUS = HERE / "corpus"
IDX = HERE / "nk.idx.json"
RUNS = 3

FULL_QUERIES = [
    "TODO_FIXME_ALPHA",
    "needle_1|needle_2|needle_3",
    "fn parse_config",
    "config",
]


def run(cmd, cwd):
    t0 = time.perf_counter()
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return p, (time.perf_counter() - t0) * 1000.0


def norm(p):
    p = p.lstrip("./")
    if p.startswith("corpus/"):
        p = p[len("corpus/"):]
    return p


def parse_nk_json(stdout):
    out = set()
    for line in stdout.splitlines():
        if line.strip():
            o = json.loads(line)
            out.add((norm(o["path"]), o["line"], o["text"]))
    return out


def nk_scan_set(q):
    p, _ = run([str(NK), "--", q, "."], CORPUS)
    assert p.returncode in (0, 1), p.stderr[:300]
    return parse_nk_json(p.stdout)


def nk_indexed_set(q):
    p, _ = run([str(NK), "--use-index", str(IDX), "--", q, "corpus"], HERE)
    assert p.returncode in (0, 1), p.stderr[:300]
    return parse_nk_json(p.stdout)


def rg_set(q):
    p, _ = run(["rg", "--json", "--", q, "."], CORPUS)
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


def med(cmd, cwd):
    run(cmd, cwd)
    return statistics.median(run(cmd, cwd)[1] for _ in range(RUNS))


def main():
    assert IDX.exists(), "build index first: nkg index corpus --index nk.idx.json"
    print("== gate A: oracle (indexed full vs rg full) ==")
    a_ok = True
    for q in FULL_QUERIES:
        r, g = rg_set(q), nk_indexed_set(q)
        ok = r == g
        a_ok = a_ok and ok
        print(f"  {q:28s} matches={len(r):6d} {'EQUAL' if ok else f'DIVERGE rg-only={len(r-g)} nk-only={len(g-r)}'}")
    print("== gate B: selective total ms (scan vs indexed, incl. load) ==")
    for q in ["TODO_FIXME_ALPHA", "needle_1|needle_2|needle_3"]:
        s = med([str(NK), "--", q, "."], CORPUS)
        x = med([str(NK), "--use-index", str(IDX), "--", q, "corpus"], HERE)
        print(f"  {q:28s} scan={s:6.1f} indexed={x:6.1f} {'WIN' if x <= s else 'LOSE'}")
    print("== gate C: top-k latency vs rg full ==")
    r = med(["rg", "--json", "--", "config", "."], CORPUS)
    k = med([str(NK), "--use-index", str(IDX), "--top", "20", "--", "config", "corpus"], HERE)
    print(f"  config top-20 indexed={k:6.1f} vs rg-full={r:6.1f} {'WIN' if k <= r else 'LOSE'}")
    r2 = med(["rg", "--json", "--", "fn parse_config", "."], CORPUS)
    k2 = med([str(NK), "--use-index", str(IDX), "--top", "10", "--", "fn parse_config", "corpus"], HERE)
    print(f"  parse_config top-10 indexed={k2:6.1f} vs rg-full={r2:6.1f} {'WIN' if k2 <= r2 else 'LOSE'}")
    print("GATE A:", "PASS" if a_ok else "FAIL")


if __name__ == "__main__":
    main()
