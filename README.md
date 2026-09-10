# NKGREP

Top-n,k ranked code search. A trigram index finds candidate files, best-first
verify ranks them; on covered query classes (plain literals) every result set
equals ripgrep. n,k is the whole pitch: the k best answers with proof, in
milliseconds.

## Performance

- Selective queries (medians of 5 runs + warmup, Apple M2, same session):
  cold 6.3 ms / hot 3.8 ms vs rg 30.8 ms vs ugrep 30.8 ms (146 matches, identical sets).
- Heavy high-match query, full dump vs top-20 (same method): full dump
  cold 40.3 ms / hot 54.7 ms vs rg 60.4 ms vs ugrep 31 ms; top-20
  cold 41.6 ms / hot 10.6 ms (51410 matches, identical sets).
- Ranked top-k on covered classes returns the same match sets as ripgrep;
  ranking applies on top. See `bench/` for the benchmark scripts.

## Install

From crates.io:

```bash
cargo install nkgrep
```

From source:

```bash
cargo build --release
./target/release/nkgrep --version
```

## Quickstart

Build an index, serve it, query the best 20 hits:

```bash
nkgrep index . --index nkgrep.idx.json
nkgrep serve --index nkgrep.idx.json --port 17632 &
nkgrep --port 17632 --top 20 -- 'pattern'
```

One-shot search without a server (cold index or plain scan):

```bash
nkgrep -- 'pattern' src
nkgrep --use-index nkgrep.idx.json -- 'pattern' .
```

Default output is one JSON object per match on stdout:

```json
{"path":"a.txt","line":1,"text":"hello world","score":-4.000001}
```

A diagnostics line always goes to stderr:

```text
nkgrep: 2 matches in 2 files, 2 ms (index load 0 ms)
```

## Subcommands

| Command | One-line | Example |
|---|---|---|
| `index <path> [--index FILE]` | Walk path, write trigram index (default `.nkgrep.json`; skips binary files) | `nkgrep index . --index nkgrep.idx.json` |
| `serve --index FILE --port PORT` | Serve index on 127.0.0.1:PORT | `nkgrep serve --index nkgrep.idx.json --port 17632 &` |

## Flag reference

Search: `nkgrep [options] [--] <pattern> [path]`. With any `-e`/`-f`,
patterns come from the options and all positionals are paths (zero or one).

### Matching
| Flag | One-line | Example |
|---|---|---|
| `-i, --ignore-case` | Case-insensitive match | `nkgrep -i -- 'hello.*world' .` |
| `-F, --fixed-strings` | All patterns are literals, never regex | `nkgrep -F -- 'literal (parens)' src` |
| `-v, --invert-match` | Print non-matching lines (forces full scan) | `nkgrep -v -- 'pattern' src` |
| `-w, --word-regexp` | Whole-word match (Unicode word boundaries) | `nkgrep -w -- 'word' src` |
| `-e PAT, --regexp PAT` | Search pattern; repeatable, branches OR (inline `(?i)` stays scoped to its pattern) | `nkgrep -e 'TODO' -e 'FIXME' src` |
| `-f FILE, --file FILE` | Patterns from FILE, one per line; repeatable; empty line matches every line; `-` reads stdin; missing file exits 2 | `nkgrep -f pats.txt src` |
| `-m N, --max-count N` | Cap matching lines per file at N (`0` matches nothing; `-c` prints capped counts; per-file, before `--top`; `-mN` attached works) | `nkgrep -m 5 -- 'pattern' src` |

Short flags cluster within their group: `-iq` means `-i` plus `-q`, `-cl`
means `-c` plus `-l`; mixed clusters (e.g. `-ci`) stay positional.

### Output control

| Flag | One-line | Example |
|---|---|---|
| `-q, --quiet, --silent` | Suppress stdout, stop at first match; exit 0/1 | `nkgrep -q -- 'pattern' src && echo found` |
| `-c, --count` | `path:count` per matching file, path-sorted | `nkgrep -c -- 'pattern' src` |
| `-l, --files-with-matches` | Matching paths only, path-sorted; wins over `-c` | `nkgrep -l -- 'pattern' src` |
| `--top N` | Print only the top N ranked matches | `nkgrep --top 20 -- 'TODO\|FIXME' .` |
| `--format json\|text` | Rendering (default `json`); `text` emits `path:line:text` in rank order, same hits/order, no score; ignored under `-c`/`-l`/`-q` | `nkgrep --format text -- 'pattern' src` |
| `--color[=WHEN]` | Highlight spans in `--format text` (`auto` default: tty only; `always`/`never` force/suppress; `ansi` aliases `always`; bare `--color` forces on; JSON never colorized) | `nkgrep --format text --color=always -- 'pattern' src \| cat` |
| `-A N, --after-context N` | N lines after each match (`-A2` attached works) | `nkgrep -A 2 -- 'pattern' src` |
| `-B N, --before-context N` | N lines before each match (`-B2` attached works) | `nkgrep -B 1 -- 'pattern' src` |
| `-C N, --context N` | N lines around each match; explicit `-A`/`-B` beats `-C` per side | `nkgrep -C 1 -- 'pattern' src` |
| `--group-separator SEP` | Separator between disjoint in-file context groups (default `--`; empty prints none) | `nkgrep -C 1 --group-separator '' -- 'pattern' src` |

### Input / traversal (six)

| Flag | One-line | Example |
|---|---|---|
| `-.`, `--hidden` | Search hidden files and directories | `nkgrep --hidden -- 'pattern' src` |
| `--no-ignore` | Skip ignore files, search everything traversal reaches | `nkgrep --no-ignore -- 'pattern' src` |
| `-L, --follow` | Follow symbolic links | `nkgrep -L -- 'pattern' src` |
| `-g GLOB, --glob GLOB` | Include/exclude paths, gitignore-style; repeatable; leading `!` excludes; `-gGLOB` attached works | `nkgrep -g '*.rs' -- 'pattern' src` |
| `-d N, --max-depth N` | Limit traversal depth (`-dN` attached works) | `nkgrep -d 2 -- 'pattern' src` |
| `--max-filesize N` | Skip files larger than N bytes (`K`/`M`/`G` suffixes, either case) | `nkgrep --max-filesize 1M -- 'pattern' src` |

### Index / server

| Flag | One-line | Example |
|---|---|---|
| `--use-index FILE` | Load index file (serve-first via daemon if registered, else local load) | `nkgrep --use-index nkgrep.idx.json -- 'pattern' .` |
| `--port PORT` | Query the daemon on PORT instead of searching locally | `nkgrep --port 17632 --top 20 -- 'pattern'` |
| `--index FILE` | Index/serve: use FILE as the index file | `nkgrep index . --index nkgrep.idx.json` |

### Meta

| Flag | One-line | Example |
|---|---|---|
| `--` | End flag scan; pattern starting with `-` is literal | `nkgrep -- '-leading-dash' src` |
| `-h, --help` | Print help to stdout, exit 0 | `nkgrep --help` |
| `-V, --version` | Print version to stdout, exit 0 | `nkgrep --version` |

More traversal examples:

```bash
nkgrep -g '!*.min.js' -- 'pattern' src
nkgrep -A 2 -B 1 -- 'pattern' src
nkgrep -- 'pattern' - < input.txt
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | At least one match; also `--help`/`--version` output, and a closed stdout pipe (e.g. `\| head`) exits 0 quietly |
| 1 | No matches (including `-q` with none found) |
| 2 | Usage error, bad regex, invalid `-m`/`-d`/`-A`/`-B`/`-C` number, bad `--format`/`--color`/`--max-filesize` value, missing `-f` file, unreadable or stale index, unresolvable root, bind/connect failure, other I/O error |

Usage errors print usage to stderr; bad patterns and values report as
`nkgrep: <msg>`.

## Man page

`man/nkgrep.1` documents the same flags, exit codes, and examples; see also
`rg(1)`, `grep(1)`.

## Status

Pre-release. APIs and output formats may change before the first stable release.
