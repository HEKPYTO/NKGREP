# src

Two files. `main.rs` is the whole binary (~5k lines); `prefilter.rs`
is the trigram set logic shared by rank paths.

## Pipeline

```
walk -> index -> rank -> verify -> emit
```

- **walk** (`walk_files`): respects `.gitignore`, skips hidden unless
  `--hidden`, follows symlinks only with `-L`. Never descends `.git/`
  without `--no-ignore`.
- **index** (`nkg index`): per-file trigram sets merged into sorted
  posting lists. Two formats: JSON (default `.nkg.json`, debuggable)
  and binary `.bin` (smaller, faster load). Root fingerprint embedded;
  a moved tree is refused loudly, never silently empty.
- **rank**: idf-weighted trigram overlap plus path bonus minus depth.
  Match score = file score − line/1e6, which is what makes top-k
  early exit provable: files verify in descending file score and the
  loop stops once no remaining file can beat the k-th best hit.
- **verify**: parallel file search (`verify_one_raw`), then emit.
  Binary files (NUL in first 8 KiB) are skipped identically on both
  indexed and scan paths.
- **emit**: JSON Lines by default (`--format json`), `path:line:text`
  with `--format text`. Scores always computed; text mode just
  doesn't print them.
- **serve** (`nkg serve`): holds the index in memory, answers over
  TCP on 127.0.0.1. `--use-index` prefers a live daemon and falls
  back to cold automatically.

## Extension

- New flag: arg-parse loop in `main`, one `usage()` line, one
  `print_help()` entry, then thread through cold + serve paths.
- New output shape: beside `emit_raw_with_path`, keep JSON
  byte-identical on the default path.
- New matcher option: `build_matcher`, with an indexed==scan probe
  (regex-syntax queries must fall back to full scan when trigrams
  can't prove candidacy — see `branch_needs_fallback`).

## Invariants (Do Not Break)

- Indexed full search equals scan full search on every query
  (`tests/oracle.rs` enforces it).
- Top-k early exit never displaces a true top-k hit.
- Success-path stdout bytes only change with a format flag.
