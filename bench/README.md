# Benchmarks

## Headline numbers

Measured on an idle 32-core Linux host (`nproc` 32, load below
5, `sleep(100ms)` jitter 0.06 ms over 10 samples - tight enough to
resolve a 4 ms gap), 11 interleaved rounds, every match set identical to
ripgrep's. `python3 bench/race.py` re-runs the race and prints the
host conditions and the parity gate alongside it.

Full race against every indexed and scan competitor, all match
sets identical, medians of 11 interleaved rounds. Each number is one
whole CLI invocation - process spawn, index load, search and output -
against a prebuilt index, which is the honest one-shot comparison:

| query | nkg | ripgrep | ugrep | zoekt |
| --- | --- | --- | --- | --- |
| `TODO_FIXME_ALPHA` | **3.9 ms** | 8.0 ms | 12.6 ms | 29.3 ms |
| `needle_1\|needle_2\|needle_3` | **3.5 ms** | 7.7 ms | 10.3 ms | 34.0 ms |
| `fn parse_config` | **3.3 ms** | 7.7 ms | 10.7 ms | 32.9 ms |
| ~~`config` (51,410 hits)~~ | withdrawn | — | — | — |

The `config` row is withdrawn, not lost. Hand-timed on the same host it
put `nkg` at 14 ms and `ugrep` at 7 ms — the reverse of the race's 25.6
and 30.5. The two disagree and the cause is unresolved, so the row is
withdrawn rather than published as either. The three selective rows agree
with every other measurement taken, which is why they stay.

Every indexed contender is measured on its **indexed** path — index
against index — and every match set is gated equal to ripgrep's before
it is timed. Ripgrep is the scan baseline; it has no index.
`nkg` is fastest on all three selective queries.
The index is **2.3 MB against zoekt's 22.7 MB** and `ugrep`'s
3.1 MB — smaller than both for the same answers.

`tgrep` has no row yet: this run predated the harness fix for a flag
`tgrep` rejects, so it was dropped at the parity gate. Run
`python3 bench/race.py` again for the five-tool table.

Most of `nkg`'s 3.3-3.9 ms is process spawn. `nkg` reports its own
index load as `index load 0 ms` — under a millisecond, re-read on every
invocation — so spawn and search split the budget. `nkg serve` holds
the index resident across queries instead of paying that per query.

These margins hold on an idle host, and they depend on
host load: on a busy machine the ranking between tools changes from
round to round, so measure on a quiet box before quoting any of them.

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
| `race.py` | Full parity-gated race vs indexed and scan competitors (11 interleaved rounds) |
| `make_chart.py` | Draws `benchmark.png` from one `race.py` run, transcribed by hand |
| `benchmark.png` | The chart the root README shows |
| `VERSIONS.md` | Exact tool builds and paths the numbers were taken on |

Everything else under `bench/` is generated or per-run and is not in the
repository: `gen_corpus.py` writes `corpus/`, `corpus-git/` and
`corpus-tgrep/`, each benchmark builds its own `nk.idx.bin`, and the
scripts keep their numbers in a local, untracked file. Clone and run
`gen_corpus.py` first; every other script says so if it finds nothing.

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

## Query Set

Every script here uses the same four queries, from highly selective to
match-everything:

| Query | Selectivity |
| --- | --- |
| `TODO_FIXME_ALPHA` | ~146 matching lines |
| `needle_1\|needle_2\|needle_3` | ~86 matching lines |
| `fn parse_config` | ~60 matching lines |
| `config` | matches all over the corpus |

Exact counts for your run are printed by each script, so you can confirm
the corpus matches the table above.

`benchmark.png` plots the first three only. `config` is withheld: two
measurements of it disagreed (see "How to read" below).

## Scripts and commands

Build the binary first (all scripts expect it at
`target/release/nkg`):

```sh
cargo build --release
```

Run every script from the repo root (`bench.py`, `bench_index.py`,
`bench_universe.py`, `race.py`) — each one locates the
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
cd bench && ../target/release/nkg index corpus --index nk.idx.bin
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


## How to read `bench/benchmark.png`

- **Groups on the horizontal axis are queries**: `TODO_FIXME_ALPHA`,
  `needle_1 | needle_2 | needle_3`, `fn parse_config`.
- **Bars within a group are tools**: `nkg`, `ripgrep`, `ugrep`, `zoekt`.
  Every one of them is measured on its indexed path — `ugrep --index`,
  `zoekt -index_dir`. Ripgrep is the exception: it has no index, so it
  is the scan baseline and the parity reference.
- **Bar height is median milliseconds — lower is better.** Each bar is
  labeled with its value.
- **Every plotted tool passed match-set equality against ripgrep before
  it was timed.** A tool that diverged is dropped, never plotted.

The numbers in the chart are transcribed by hand from one `race.py` run;
`make_chart.py` does not re-measure. Re-running `race.py` prints fresh
numbers and writes no chart — race again and you must edit `MS` in
`make_chart.py` yourself. That is deliberate: a chart regenerated from
an untracked file is one nobody can reproduce or correct, which is what
made the previous public chart wrong.

`tgrep` is absent because `race.py` passed it a flag its build rejects.
The flag is fixed; the race has not been repeated with it.

`config`, which matches all 51,410 lines, is **not plotted**. `race.py`
reported nkg 25.6 ms and ugrep 30.5 ms; hand timing on the same host
reported nkg 14 ms and ugrep 7 ms — the reverse. The cause is
unresolved, so it is named rather than drawn.

The tool versions behind the chart are printed in its footer.

## Reproducibility method

Numbers are only comparable when measured under the same conditions.
The convention every script here follows:

1. **Same machine, back to back.** All tools in one comparison run in
   the same session, alternating order where it matters, with no other
   heavy load. Never compare a number from one machine against a number
   from another.
2. **One discarded warmup, then medians.** Each script runs the command
   once unmeasured (warming the page cache and any server state), then
   measures N identical runs — 5 in `bench.py`, 3 in `bench_index.py`
   and `bench_universe.py` — and reports the median, so a single slow outlier
   cannot swing the result. `race.py` instead runs 11 interleaved rounds by
   default (`--rounds` adjusts it, as does `--runs` for `--live` chart runs).
3. **Same corpus, same counts.** The corpus generator is deterministic,
   so match counts are stable across rebuilds; each script prints the
   reference match counts so you can confirm your corpus agrees before
   trusting the timings.
4. **Equality first, speed second.** A faster time with a divergent
   match set is a failure, not a win — check the EQUAL/DIVERGE column
   before reading any milliseconds.
