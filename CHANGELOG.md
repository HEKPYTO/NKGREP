# Changelog

## Unreleased

- Binary index (`.bin`) is the default everywhere: quickstart, man,
  usage, and every benchmark runs on it (the JSON format stays
  for debugging). Release profile uses fat LTO with `codegen-units = 1`.
- New `--stats`: query plan and candidate counts on stderr (indexed only).
- `--use-index` with `--port` is rejected (exit 2), never silently picked.
- Fixed `-l` with `--invert-match` dropping the invert filter.
- Benchmarks: parity-gated race table vs ripgrep, ugrep, and zoekt
  (11 interleaved rounds, `bench/race.py`); tgrep harness reads stdout and
  passes an accepted flag set; ugrep measured on its indexed path.
- Index format NKGREP06: derivable posting field dropped (~12% smaller
  index, ~16% faster load); obsolete header constant and build path cut.
- Man page: fixed date macro and a skipped paragraph; documented `--stats`,
  `--color WHEN`, attached `-mN`/`-dN`/`-gGLOB`, `--no-hidden`,
  `--no-follow`, `--no-pcre2`/`--no-encoding`, and the `.nkg.bin` default.
- Tests: 85 (53 unit + 32 oracle), green; serve covered with `-v`,
  `-l -v`, and `--top -m` against cold.
