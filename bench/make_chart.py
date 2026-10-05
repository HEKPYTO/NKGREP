"""Draw the query-latency chart the root README shows.

The numbers below are transcribed BY HAND from one `bench/race.py` run.
Re-running `race.py` prints fresh numbers and writes no chart; race again
and you must edit `MS` yourself, then re-run this script. That is
deliberate - a chart auto-regenerated from an untracked file is a picture
nobody can reproduce or correct, which is exactly what made the previous
public chart wrong.

    python3 bench/make_chart.py

Withheld on purpose: the `config` query, which matches all 51,410 lines.
`race.py` reported nkg 25.6 ms and ugrep 30.5 ms; hand timing on the same
host reported nkg 14 ms and ugrep 7 ms - the reverse. Cause unresolved,
so it is named in the footer instead of plotted.
"""
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = Path(__file__).parent
OUT = HERE / "benchmark.png"

# One race.py run on an idle 32-core Linux host (nproc 32, load < 5,
# sleep(100ms) jitter 0.065 ms). Transcribed by hand; see bench/README.md.
GROUPS = ["TODO_FIXME_ALPHA", "needle_1 | needle_2 | needle_3", "fn parse_config"]
SERIES = [
    ("nkg", "#8ec7f2", [3.9, 3.5, 3.3]),
    ("ripgrep", "#4a9ee0", [8.0, 7.7, 7.7]),
    ("ugrep", "#0b62c4", [12.6, 10.3, 10.7]),
    ("zoekt", "#0a3d8f", [29.3, 34.0, 32.9]),
]
FOOTER = (
    "nkg: `nkg --use-index bench/nk.idx.bin -- <q> corpus`   ·   "
    "ripgrep: `rg --json -- <q> corpus`   ·   "
    "ugrep: `ugrep --index -r -n <q> corpus`   ·   zoekt: `zoekt -index_dir <dir> <q>`\n"
    "versions: nkg (this build) · ripgrep 15.2.0 · ugrep 7.8.5 · zoekt 153817f643cd\n"
    "every match set gated equal to ripgrep's before timing. tgrep omitted: the harness "
    "passed it a flag it rejects (since fixed, run not repeated).\n"
    "not plotted - `config`, which matches all 51,410 lines: race.py gave nkg 25.6 ms and "
    "ugrep 30.5 ms, hand timing on the same host gave nkg 14 ms\nand ugrep 7 ms. The two "
    "disagree, cause unresolved."
)


def main():
    fig, ax = plt.subplots(figsize=(13.0, 6.4), dpi=120)
    n = len(SERIES)
    width = 0.80 / n
    xs = list(range(len(GROUPS)))

    for i, (name, colour, vals) in enumerate(SERIES):
        offs = [x + (i - (n - 1) / 2) * width for x in xs]
        bars = ax.bar(offs, vals, width, label=name, color=colour, zorder=3)
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v + 0.5, f"{v:g}",
                    ha="center", va="bottom", fontsize=9.5, zorder=4)

    ax.set_xticks(xs)
    ax.set_xticklabels(GROUPS, fontsize=11)
    ax.set_ylabel("min-of-N wall time (ms)", fontsize=11)
    ax.set_ylim(0, 40)
    ax.set_title(
        "nkg is fastest on every query plotted — indexed vs indexed, match sets equal"
        "  ·  LOWER IS BETTER",
        fontsize=13, pad=36, loc="left",
    )

    leg = ax.legend(
        title="series (nkg measured on its indexed path)", ncol=4,
        loc="upper center", bbox_to_anchor=(0.5, 1.0), fontsize=10,
        title_fontsize=9.5, frameon=False,
    )
    leg.get_title().set_color("#333333")

    ax.grid(axis="y", color="#dcdcdc", linewidth=0.7, zorder=0)
    ax.set_axisbelow(True)
    fig.text(0.008, 0.055, FOOTER, fontsize=7.6, color="#333333", va="top")

    fig.tight_layout(rect=(0, 0.12, 1, 0.97))
    fig.savefig(OUT, bbox_inches="tight", facecolor="white")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()