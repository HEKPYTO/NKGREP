# tests

## Contract

`oracle.rs` (match-set equality suite) enforces the one rule everything else rests on:
**indexed full search must equal scan full search on every query.**
Any divergence fails the suite.

## Fixture (100-File Fixture in oracle.rs — Not the 3,000-File Bench Corpus)

A planted tree (4 packages × 25 files × 20 lines = 100 text files) plus
a binary file, built fresh per run under the system temp dir. This is
separate from the 3,000-file bench corpus under `bench/corpus/` — bench
numbers come from that corpus, never from this fixture. Queries cover
plain literals, alternations, case/regex forms, and flag matrix
cases (`flag_matrix_equals_scan`, 18 shapes and counting).

## Gates (bench/bench_index.py)

- **A**: indexed full vs ripgrep full — sets must be equal.
- **B**: selective indexed vs scan — indexed must win.
- **C**: top-k indexed vs ripgrep full — top-k must win.

```sh
cargo test
(cd bench && ../target/release/nkg index corpus --index nk.idx.json)
python3 bench/bench_index.py     # run from repo root
```
