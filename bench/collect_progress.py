"""Progress plot: nkg split (scan / cold indexed / hot serve) + top-20.

Default run is fully frozen and deterministic: every plotted bar comes from
the table below, and every table cell is upserted into local runs/progress.csv,
so all claims in local runs/progress.png are data rows. Re-running replaces rows
by (date, source, query, tool) key -- never duplicates -- and regenerates
the PNG. Legacy single-bar `tool=nkgrep` rows are pruned: the frozen record
marks the old single serve row superseded by the split.

Frozen provenance (3,000-file corpus, recorded 2026-09-09):
- selective groups: scan medians measured 2026-09-09; indexed and serve
  rows from the same frozen record (includes corrections to two stale
  values the previous script carried).
- heavy-full: indexed and serve rows from the evening record 2026-09-09
  (streamed serve); the older rows stay in the CSV beside the plotted rows.
- heavy-top20: indexed top-20 plus a full-scan reference from the same session.
- rerun noise note: one rerun differed by about a millisecond on a single
  cell; results unchanged either way (see the footnotes on the detailed chart).

Pass --live to remeasure the scan/tgrep/rg/ugrep full-group cells with the
bench harness on this machine (slow, needs the full tool set);
those rows upsert under --date/--live and overlay the frozen table.

Pass --public-simple to also write bench/benchmark.png: a minimal chart with
plain labels (nkgrep scan / nkgrep indexed / nkgrep serve + tgrep / rg / ugrep) and no footnotes.
Deterministic from the same frozen table.

Matplotlib only (no seaborn).
"""

import argparse
import csv
import statistics
import subprocess
import sys
import time
from datetime import date
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parent
OUT_DIR = ROOT / "output"
CSV = OUT_DIR / "results.csv"
PNG = OUT_DIR / "results.png"
PUBLIC_PNG = HERE / "results.png"

GROUPS = ["sel-146", "sel-86", "sel-60", "heavy-full", "heavy-top20"]
ORDER = [
    "nk-scan",
    "nk-cold-bin",
    "nk-cold-json",
    "nk-hot",
    "tgrep",
    "rg",
    "rg-full",
    "ugrep",
    "ugrep-full",
]

# (median_ms, source, sdate).
FROZEN = {
    "sel-146": {
        "nk-scan": (31.6, "live", "2026-09-09"),
        "nk-cold-bin": (6.4, "handoff", "2026-09-09"),
        "nk-hot": (5.0, "handoff", "2026-09-09"),
        "tgrep": (7.6, "handoff", "2026-09-09"),
        "rg": (29.4, "handoff", "2026-09-09"),
        "ugrep": (30.4, "handoff", "2026-09-09"),
    },
    "sel-86": {
        "nk-scan": (31.4, "live", "2026-09-09"),
        "nk-cold-bin": (6.1, "handoff", "2026-09-09"),
        "nk-hot": (4.7, "handoff", "2026-09-09"),
        "tgrep": (9.4, "handoff", "2026-09-09"),
        "rg": (29.0, "handoff", "2026-09-09"),
        "ugrep": (31.5, "handoff", "2026-09-09"),
    },
    "sel-60": {
        "nk-scan": (31.9, "live", "2026-09-09"),
        "nk-cold-bin": (5.9, "handoff", "2026-09-09"),
        "nk-hot": (3.9, "handoff", "2026-09-09"),
        "tgrep": (8.4, "handoff", "2026-09-09"),
        "rg": (27.4, "handoff", "2026-09-09"),
        "ugrep": (32.1, "handoff", "2026-09-09"),
    },
    "heavy-full": {
        "nk-scan": (63.0, "live", "2026-09-09"),
        "nk-cold-bin": (46.7, "crown", "2026-09-09"),
        "nk-hot": (66.9, "crown", "2026-09-09"),
        "tgrep": (136.2, "handoff", "2026-09-09"),
        "rg": (56.4, "handoff", "2026-09-09"),
        "ugrep": (39.9, "handoff", "2026-09-09"),
    },
    "heavy-top20": {
        "nk-cold-json": (57.2, "gatec", "2026-09-09"),
        "nk-cold-bin": (49.0, "handoff", "2026-09-09"),
        "nk-hot": (35.3, "handoff", "2026-09-09"),
        "rg-full": (60.5, "gatec", "2026-09-09"),
        "ugrep-full": (39.9, "handoff", "2026-09-09"),
    },
}

LEGEND = {
    "nk-scan": "nk scan (`nkg -- Q .`)",
    "nk-cold-bin": "nk cold-bin (`--use-index .bin`)",
    "nk-cold-json": "nk cold-json (`--use-index .json --top 20`)",
    "nk-hot": "nk hot-serve (`serve :18981`)",
    "tgrep": "tgrep 1.0.5 (serve)",
    "rg": "rg",
    "rg-full": "rg full (gate-C session)",
    "ugrep": "ugrep 7.8.4",
    "ugrep-full": "ugrep full (latency ctx)",
}
COLORS = {
    "nk-scan": "#9ecae1",
    "nk-cold-bin": "#3182bd",
    "nk-cold-json": "#6baed6",
    "nk-hot": "#08306b",
    "tgrep": "#ff7f0e",
    "rg": "#2ca02c",
    "rg-full": "#2ca02c",
    "ugrep": "#d62728",
    "ugrep-full": "#d62728",
}

QUERIES = {
    "sel-146": "TODO_FIXME_ALPHA",
    "sel-86": "needle_1|needle_2|needle_3",
    "sel-60": "fn parse_config",
    "heavy-full": "config",
    "heavy-top20": "config --top 20",
}
# query string per short label (for --live mapping).
QUERY_OF = {g: QUERIES[g] for g in GROUPS if g != "heavy-top20"}

FOOT_INVOC = (
    "nk-scan: `nkg -- <q> .` in bench/corpus | "
    "nk-cold-bin: `nkg --use-index bench/nk.idx.bin -- <q> corpus` in bench/ | "
    "nk-hot: `serve --index bench/nk.idx.json --port 18981`, query `--use-index <json> -- <q> corpus` | "
    "tgrep: `tgrep -n -- <q> .` via serve in bench/corpus-tgrep | "
    "rg: `rg --json -- <q> .` | ugrep: `ugrep -r -n -- <q> corpus`"
)
FOOT_QUERY = (
    "sel-146 TODO_FIXME_ALPHA - sel-86 needle_1|needle_2|needle_3 - "
    "sel-60 fn parse_config - heavy-full config - heavy-top20 config --top 20 "
    "(rg-full/ugrep-full are full-scan latency context, less work than top-20 claims none)"
)
FOOT_SRC = (
    "sources, all oracle EQUAL: scoreboard HANDOFF.md frozen 2026-09-09 (cold-bin/hot/tgrep/rg/ugrep); "
    "heavy-full crown 2026-09-09 (cold-bin 46.7 + hot 66.9, streamed serve + verify reuse + BufWriter emission); "
    "nk-scan = live bench_universe medians 2026-09-09; "
    "top-20 cold-json 57.2 + rg-full 60.5 = bench_index.py gate-C same session; "
    "ugrep heavy-full plots 39.9 frozen (live rerun 38.8, run noise); "
    "hot top-20 35.3 beat rg-full 58.4 verdict session and 60.5 gate-C session; "
    "verify 2026-09-09 late (load ~7, source=verify in CSV): cold-bin heavy-full 57.3 "
    "vs same-session ugrep 49.5 (honest loss holds), hot top-20 38.8 vs rg-full 64.4 "
    "(WIN), hot selective 5.5/5.4/4.6 vs tgrep 7.5/6.6/7.5 (WIN all three)."
    " parity 2026-09-10 (source=parity in CSV): cold-bin heavy-full 52.7 vs "
    "same-session ugrep 35.9 stage pair, superseded by 9x A/B interleave cold "
    "48.0 vs ugrep 43.0 overlapping (PARITY, first non-loss; frozen 46.7 vs "
    "39.9 stands); hot heavy-full 44.7 vs tgrep 131.0 (2.9x) and rg 54.3; "
    "hot top-20 9.9 best in series (WIN vs rg 54.3); hot selective 4.7/3.9/3.8 "
    "WINs all three vs tgrep 6.8/6.2/6.1; sel-146 cold 17.9 spike (standalone "
    "recheck 5.9, noise)."
)


def live_medians(runs):
    """Measure fresh medians with the bench harness."""
    sys.path.insert(0, str(HERE))
    import bench_universe as bu

    bu.setup_git_corpus()
    ref = {}
    medians = {}
    oracle_ok = True
    with bu.TgrepServe():
        for name in ("rg", "nk", "tgrep", "ugrep"):
            for short, q in QUERY_OF.items():
                if q not in ref:
                    ref[q] = bu.rg_set(q)
                got = bu.tool_set(name, q)
                if got != ref[q]:
                    oracle_ok = False
                    print(f"ORACLE DIVERGE: {name} {short}", flush=True)
                    continue
                cwd, argv, _ = bu.TOOLS[name]
                bu.run(argv(q), cwd)  # warmup
                ts = [bu.run(argv(q), cwd)[1] for _ in range(runs)]
                label = {"nk": "nk-scan"}.get(name, name)
                medians.setdefault(short, {})[label] = round(statistics.median(ts), 1)
    return medians, ("EQUAL" if oracle_ok else "DIVERGE")


def frozen_rows():
    rows = []
    for group, cells in FROZEN.items():
        for series, (val, source, sdate) in cells.items():
            rows.append(
                {
                    "date": sdate,
                    "source": source,
                    "tool": series,
                    "query": group,
                    "median_ms": str(val),
                    "oracle": "EQUAL",
                }
            )
    return rows


def load_rows():
    if not CSV.exists():
        return []
    with open(CSV, newline="") as f:
        return list(csv.DictReader(f))


def save_rows(new_rows):
    key = lambda r: (r["date"], r["source"], r["query"], r["tool"])
    fresh = {key(r) for r in new_rows}
    rows = [r for r in load_rows() if key(r) not in fresh and r["tool"] != "nkgrep"]
    rows.extend(new_rows)
    rows.sort(key=lambda r: (r["date"], r["source"], r["query"], r["tool"]))
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(CSV, "w", newline="") as f:
        w = csv.DictWriter(
            f, fieldnames=["date", "source", "tool", "query", "median_ms", "oracle"]
        )
        w.writeheader()
        w.writerows(rows)


def plot(table):
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    width = 0.11
    fig, ax = plt.subplots(figsize=(12, 7))
    for gi, group in enumerate(GROUPS):
        series = [s for s in ORDER if s in table[group]]
        n = len(series)
        for i, s in enumerate(series):
            v = table[group][s]
            x = gi + (i - (n - 1) / 2) * width
            b = ax.bar(
                x,
                v,
                width=width * 0.92,
                label=LEGEND[s] if gi == 0 or s == "nk-cold-json" and gi == 4 else None,
                color=COLORS[s],
                edgecolor="black" if s == "nk-hot" else "none",
                linewidth=1.2 if s == "nk-hot" else 0.0,
            )
            ax.text(
                b[0].get_x() + b[0].get_width() / 2,
                v + max(1.5, v * 0.02),
                f"{v}",
                ha="center",
                va="bottom",
                fontsize=7,
            )

    # Annotation on heavy-full; annotation on heavy-top20.
    nk, ug = table["heavy-full"]["nk-cold-bin"], table["heavy-full"]["ugrep"]
    ax.annotate(
        f"honest loss: cold-bin {nk} vs ugrep {ug}\n({nk - ug:.1f} ms to close)",
        xy=(3, ug),
        xytext=(1.4, max(nk, ug) * 0.78),
        ha="center",
        fontsize=8,
        arrowprops=dict(arrowstyle="->", color="black"),
        bbox=dict(boxstyle="round,pad=0.3", fc="wheat", alpha=0.8),
    )
    hot, rgf = table["heavy-top20"]["nk-hot"], table["heavy-top20"]["rg-full"]
    ax.annotate(
        f"hot top-20 {hot} vs rg-full {rgf}",
        xy=(4, rgf),
        xytext=(4, rgf * 1.28),
        ha="center",
        fontsize=8,
        arrowprops=dict(arrowstyle="->", color="black"),
        bbox=dict(boxstyle="round,pad=0.3", fc="honeydew", alpha=0.9),
    )

    ax.set_xticks(list(range(len(GROUPS))))
    ax.set_xticklabels(GROUPS)
    ax.set_ylabel("median wall time (ms)")
    ax.set_title("nkg split (scan / cold-bin / hot-serve) + gate-C top-20 — oracle EQUAL")
    handles, labels = ax.get_legend_handles_labels()
    seen, hh, ll = set(), [], []
    for h, lb in zip(handles, labels):
        if lb not in seen:
            seen.add(lb)
            hh.append(h)
            ll.append(lb)
    ax.legend(hh, ll, title="series (bold border = hot-serve)", fontsize=7)
    top = max(v for g in GROUPS for v in table[g].values()) * 1.22
    ax.set_ylim(0, top)
    fig.text(0.01, 0.075, FOOT_INVOC, fontsize=6, color="dimgray", wrap=True,
             ha="left", va="bottom")
    fig.text(0.01, 0.045, FOOT_QUERY, fontsize=6, color="dimgray", wrap=True,
             ha="left", va="bottom")
    fig.text(0.01, 0.005, FOOT_SRC, fontsize=6, color="dimgray", wrap=True,
             ha="left", va="bottom")
    fig.tight_layout(rect=[0, 0.09, 1, 1])
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fig.savefig(PNG, dpi=150)
    plt.close(fig)
    print(f"wrote {PNG}")


SIMPLE_LABELS = {
    "nk-scan": "nkgrep scan",
    "nk-cold-bin": "nkgrep indexed",
    "nk-cold-json": "nkgrep indexed",
    "nk-hot": "nkgrep serve",
    "tgrep": "tgrep",
    "rg": "rg",
    "rg-full": "rg",
    "ugrep": "ugrep",
    "ugrep-full": "ugrep",
}


def plot_simple(table):
    """Minimal public chart: plain labels, value bars."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    width = 0.11
    fig, ax = plt.subplots(figsize=(12, 5))
    seen = set()
    for gi, group in enumerate(GROUPS):
        series = [s for s in ORDER if s in table[group]]
        n = len(series)
        for i, s in enumerate(series):
            v = table[group][s]
            x = gi + (i - (n - 1) / 2) * width
            label = SIMPLE_LABELS[s] if SIMPLE_LABELS[s] not in seen else None
            seen.add(SIMPLE_LABELS[s])
            b = ax.bar(x, v, width=width * 0.92, label=label, color=COLORS[s])
            ax.text(
                b[0].get_x() + b[0].get_width() / 2,
                v + max(1.5, v * 0.02),
                f"{v}",
                ha="center",
                va="bottom",
                fontsize=7,
            )
    ax.set_xticks(list(range(len(GROUPS))))
    ax.set_xticklabels(GROUPS)
    ax.set_ylabel("median ms")
    ax.set_title("Search latency (median ms, lower is better)")
    top = max(v for g in GROUPS for v in table[g].values()) * 1.32
    ax.legend(fontsize=7)
    ax.set_ylim(0, top)
    fig.tight_layout()
    fig.savefig(PUBLIC_PNG, dpi=150)
    plt.close(fig)
    print(f"wrote {PUBLIC_PNG}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--live", action="store_true", help="measure fresh medians")
    ap.add_argument("--runs", type=int, default=3, help="per-query runs for --live")
    ap.add_argument("--date", default=str(date.today()), help="date key for --live rows")
    ap.add_argument("--public-simple", action="store_true", help="also write bench/benchmark.png")
    args = ap.parse_args()

    t0 = time.perf_counter()
    table = {g: {s: v for s, (v, _, _) in cells.items()} for g, cells in FROZEN.items()}
    new_rows = frozen_rows()
    source = "frozen"
    if args.live:
        medians, oracle = live_medians(args.runs)
        source = f"live ({oracle})"
        live_rows = []
        for group, cells in medians.items():
            for series, val in cells.items():
                table[group][series] = val
                live_rows.append(
                    {
                        "date": args.date,
                        "source": "live",
                        "tool": series,
                        "query": group,
                        "median_ms": str(val),
                        "oracle": oracle,
                    }
                )
        new_rows = live_rows
    save_rows(new_rows)
    plot(table)
    if args.public_simple:
        plot_simple(table)
    print(f"done in {time.perf_counter() - t0:.1f}s (source={source})")


if __name__ == "__main__":
    main()
