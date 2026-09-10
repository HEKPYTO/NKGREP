# Benchmarks

This directory measures one thing: **does `nkg` return exactly the same
matches as ripgrep, and how fast is it?** Every script below compares
match sets against ripgrep (`rg`) and reports wall-clock time. A result
counts as good only if the match sets are equal *and* the time is
competitive.

## Contents

| Path | What it is |
| --- | --- |
| `gen_corpus.py` | Builds the synthetic corpus deterministically |
| `bench.py` | Ripgrep vs `nkg` plain scan |
| `bench_index.py` | Scan vs indexed search, plus gates A / B / C |
| `bench_universe.py` | Every installed grep-like tool vs ripgrep |
| `collect_progress.py` | Draws `bench/benchmark.png` (public) from past medians |
| `corpus/` | Synthetic corpus (generated, 3,000 files) |
| `corpus-git/` | Same text under git, for `git grep` comparisons |
| `corpus-tgrep/` | Same text served by a `tgrep` server |
| `nk.idx.json` / `nk.idx.bin` | Prebuilt index files over `corpus/` |
| `archived runs/` | Dated example result snapshots |

## Corpora

The main corpus is synthetic so that results are stable and every tool
walks the exact same files: plain UTF-8 text, no hidden files, no
ignore files, so walker differences between tools drop out and the
comparison is pure search.

- Layout: 20 `pkg_NN/` directories × 150 files × 40 lines = **3,000 files**,
  about 120,000 lines. Every fifth package nests its files one level
  deeper (`deep/` instead of `flat/`).
- Word pool: 24 common code-ish words (`config loader parser render
  cache token …`), 12 words per line.
- Planted patterns (these are what the queries below look for):
  - `TODO_FIXME_ALPHA` appended to ~5% of files,
  - `needle_1` / `needle_2` / `needle_3` sprinkled on ~3% of files,
  - the line `fn parse_config(x: int) -> bool` planted in every 10th file
    of the four deep packages (60 lines total).

Regenerate it any time (this wipes `bench/corpus/` and rebuilds it
byte-identically — the random generator uses a fixed seed):

```sh
python3 bench/gen_corpus.py
# files=3000 alpha_lines=146 needles={1: 26, 2: 31, 3: 29}
```

`corpus-git/` and `corpus-tgrep/` are copies of the same text in the
shapes those tools need (a git checkout and a served tree). You do not
build them by hand: `bench_universe.py` prepares the git copy and
starts/stops the `tgrep` server on its own each run.

## Query set

All four scripts use the same four queries, from highly selective to
match-everything:

| Query | Nickname in plots | Selectivity |
| --- | --- | --- |
| `TODO_FIXME_ALPHA` | sel-146 | ~146 matching lines |
| `needle_1\|needle_2\|needle_3` | sel-86 | ~86 matching lines |
| `fn parse_config` | sel-60 | ~60 matching lines |
| `config` | heavy-full | matches all over the corpus |

A fifth plot group, `heavy-top20`, is the query `config` with `--top 20`:
return the first 20 matches instead of the full set. The ripgrep and
ugrep bars shown next to it are their *full* runs, given as latency
context (they do strictly more work).

Exact counts for your run are printed by each script
(`reference match counts: …`), so you can confirm the corpus matches
the table above.

## Scripts and commands

Build the binary first (all scripts expect it at
`target/release/nkg`):

```sh
cargo build --release
```

Run every script from the repo root (`bench.py`, `bench_index.py`,
`bench_universe.py`, `collect_progress.py`) — each one locates the
corpus and the binary relative to itself, so no `cd` is needed. The
only step with a working-directory requirement is building the index
(next section): it runs from `bench/` so the index records `corpus`
as its root.

### `bench.py` — ripgrep vs plain scan

```sh
python3 bench/bench.py
```

For each of the four queries it checks that the `nkg` match set
(file, line, text per match) equals the ripgrep match set, then prints
median milliseconds for both tools plus three verdict lines: match-set
equality, speed (`nkg` at or under ripgrep on every query), and the
combined kill verdict (`SURVIVE` only if both pass).

### `bench_index.py` — scan vs indexed search, gates A / B / C

Build the index first. This step runs from `bench/` so the index
records `corpus` as its root — the same root the script queries:

```sh
cd bench && ../target/release/nkg index corpus --index nk.idx.json
```

Then, from the repo root:

```sh
python3 bench/bench_index.py
```

What the three gates mean, in plain words:

- **Gate A — indexed search agrees with ripgrep.** For every query, the
  full indexed result set must contain exactly the same matches as a
  full ripgrep run: same files, same line numbers, same text — no
  missing matches, no extra matches. This is match-set equality vs
  ripgrep, applied to the index path instead of the scan path.
- **Gate B — the index pays for itself on selective queries.** For the
  two selective queries, the total indexed time *including loading the
  index file* must be no slower than a plain scan with no index.
- **Gate C — early cutoff beats full work.** Asking the index for only
  the first 20 (or 10) matches of a heavy query must answer no slower
  than ripgrep's full run over the whole corpus.

The script prints `EQUAL` / `DIVERGE` per query for gate A, `WIN` /
`LOSE` timing lines for gates B and C, and a final `GATE A: PASS/FAIL`
line.

### `bench_universe.py` — every installed tool vs ripgrep

```sh
python3 bench/bench_universe.py
```

Measures `rg`, `nkg` (scan and indexed), `grep`, `git grep`, `ugrep`,
`ag`, `ack`, and `tgrep` on the four queries. Each cell is either the
median milliseconds (when that tool's match set equals ripgrep's) or a
`DIVERGE(a/b)` marker counting matches only that tool found (a) and
matches only ripgrep found (b). Tools that cannot run on this corpus
are listed under `N/A (not comparable here)` with a reason instead of
a number. Missing tools are simply skipped; only ripgrep and `nkg`
are required.

### `collect_progress.py` — the progress chart

```sh
python3 bench/collect_progress.py --public-simple
# writes local runs/progress.csv + local runs/progress.png (private, gitignored)
#   and bench/benchmark.png (the public chart, tracked in git)
```

By default this plots a stored table of past medians (no measuring —
fast and deterministic) and upserts those rows into
`local runs/progress.csv`, keyed by date, source, query, and tool, so
re-runs never duplicate rows. To measure fresh numbers on your machine
and overlay them instead (slow; needs the full tool set and
`matplotlib`):

```sh
python3 bench/collect_progress.py --live --runs 3 --date 2026-09-10
```

## How to read `bench/benchmark.png`

- **Groups on the horizontal axis are queries**: the three selective
  queries, then the heavy full query, then the heavy top-20 query.
- **Bars within a group are tools**: `nkgrep scan`, `nkgrep indexed`
  (cold index file), `nkgrep serve` (hot already-running server),
  `tgrep`, `rg`, and `ugrep`. The top-20 group additionally shows
  full-run bars as latency context.
- **Bar height is median milliseconds — shorter is faster.** Each bar
  is labeled with its value.
- **Every plotted bar passed match-set equality vs ripgrep.** A bar
  that diverged would not be plotted as a time at all.

The same run also writes `local runs/progress.png`, a detailed local-only
variant with footnotes recording the exact command, query, and session
behind each bar. It lives under `local runs/`, which is gitignored, so it
stays on your disk — `bench/benchmark.png` is the chart to share.

`local runs/progress.csv` holds the same data in tabular form
(`date, source, tool, query, median_ms`, plus the EQUAL/DIVERGE
equality column), one row per plotted bar.

`bench/archived runs/` keeps dated example snapshots of full result
printouts; each file records at the top the corpus, method, and per-run
numbers behind its verdict lines.

## Reproducibility method

Numbers are only comparable when measured under the same conditions.
The convention every script here follows:

1. **Same machine, back to back.** All tools in one comparison run in
   the same session, alternating order where it matters, with no other
   heavy load. Never compare a number from one machine against a number
   from another.
2. **One discarded warmup, then medians.** Each script runs the command
   once unmeasured (warming the page cache and any server state), then
   measures N identical runs — 5 in `bench.py`, 3 in the index and
   universe scripts — and reports the median, so a single slow outlier
   cannot swing the result. `--runs` adjusts this for `--live` chart
   runs.
3. **Same corpus, same counts.** The corpus generator is deterministic,
   so match counts are stable across rebuilds; each script prints the
   reference match counts so you can confirm your corpus agrees before
   trusting the timings.
4. **Equality first, speed second.** A faster time with a divergent
   match set is a failure, not a win — check the EQUAL/DIVERGE column
   before reading any milliseconds.
