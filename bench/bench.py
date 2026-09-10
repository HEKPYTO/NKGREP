"""Neutral bakeoff: rg --json vs nkg. Asserts identical match sets (differential
equality), reports median wall time over N runs, prints kill verdict."""
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent
NK = HERE.parent / "target" / "release" / "nkg"
CORPUS = HERE / "corpus"
RUNS = 5

QUERIES = [
    "TODO_FIXME_ALPHA",
    "needle_1|needle_2|needle_3",
    "fn parse_config",
    "config",
]


def run(cmd, cwd):
    t0 = time.perf_counter()
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    dt = (time.perf_counter() - t0) * 1000.0
    return p, dt


def rg_set(query):
    p, _ = run(["rg", "--json", "--", query, "."], CORPUS)
    assert p.returncode in (0, 1), p.stderr[:500]
    out = set()
    for line in p.stdout.splitlines():
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            continue
        if o.get("type") == "match":
            d = o["data"]
            path = d["path"]["text"].lstrip("./")
            text = d["lines"]["text"].rstrip("\n")
            out.add((path, d["line_number"], text))
    return out


def nk_set(query):
    p, _ = run([str(NK), "--", query, "."], CORPUS)
    assert p.returncode in (0, 1), p.stderr[:500]
    out = set()
    for line in p.stdout.splitlines():
        if not line.strip():
            continue
        o = json.loads(line)
        out.add((o["path"].lstrip("./"), o["line"], o["text"]))
    return out


def median_time(cmd, cwd):
    run(cmd, cwd)  # warmup, discarded
    ts = [run(cmd, cwd)[1] for _ in range(RUNS)]
    return statistics.median(ts)


def main():
    if not NK.exists():
        sys.exit("build first: cargo build --release")
    print(f"{'query':28s} {'rg_ms':>9s} {'nk_ms':>9s} {'matches':>8s} oracle")
    all_ok, all_fast = True, True
    for q in QUERIES:
        rset, gset = rg_set(q), nk_set(q)
        ok = rset == gset
        if not ok:
            print(f"  ONLY_RG={len(rset - gset)} ONLY_NK={len(gset - rset)}")
            for row in sorted(rset - gset)[:3]:
                print(f"  rg-only: {row}")
            for row in sorted(gset - rset)[:3]:
                print(f"  nk-only: {row}")
        all_ok = all_ok and ok
        rt = median_time(["rg", "--json", "--", q, "."], CORPUS)
        gt = median_time([str(NK), "--", q, "."], CORPUS)
        all_fast = all_fast and gt <= rt
        print(f"{q:28s} {rt:9.1f} {gt:9.1f} {len(rset):8d} {'EQUAL' if ok else 'DIVERGE'}")
    print("ORACLE:", "PASS identical match sets" if all_ok else "FAIL divergent sets")
    print("SPEED:", "PASS nk <= rg on every query" if all_fast else "FAIL rg faster somewhere")
    print("KILL:", "SURVIVE" if (all_ok and all_fast) else "KILL")


if __name__ == "__main__":
    main()
