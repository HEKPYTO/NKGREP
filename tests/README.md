# tests

## Contract

`oracle.rs` enforces the one rule everything else rests on:
**indexed full search must equal scan full search on every query.**
Any divergence fails the suite.

## Fixture

A planted tree (4 packages × 25 files × 20 lines) plus a binary
file, built fresh per run under the system temp dir. Queries cover
plain literals, alternations, case/regex forms, and flag matrix
cases (`flag_matrix_equals_scan`, 18 shapes and counting).

## Gates (bench/bench_index.py)

- **A**: indexed full vs ripgrep full — sets must be equal.
- **B**: selective indexed vs scan — indexed must win.
- **C**: top-k indexed vs ripgrep full — top-k must win.

Run: `cargo test` then `python3 bench/bench_index.py`.
