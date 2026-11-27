# nkgrep

[![CI](https://img.shields.io/github/actions/workflow/status/HEKPYTO/NKGREP/ci.yml?branch=main)](https://github.com/HEKPYTO/NKGREP/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/nkgrep)](https://crates.io/crates/nkgrep)
[![license](https://img.shields.io/crates/l/nkgrep)](https://crates.io/crates/nkgrep)

nkgrep is a ranked code search tool. Given a pattern, it returns the k
highest-scoring matches. It combines a trigram index with best-first
verification: on plain literal queries it returns exactly the match set
of ripgrep, ordered by relevance score.

## Quickstart

### Install

```bash
cargo install nkgrep
```

Or build it yourself (crate stays `nkgrep`, the binary is `nkg`):

```bash
cargo build --release
./target/release/nkg --version
```

```bash
# index the repo once - a .bin path writes the fast binary
# format, any other extension writes JSON
nkg index . --index .nkg.bin

# serve it in the background
nkg serve --index .nkg.bin --port 17632 &

# ask for the 20 best hits
nkg --port 17632 --top 20 -- 'TODO|FIXME'
```

No server? No problem — plain one-shot search works too:

```bash
nkg -- 'pattern' src
```

Each hit comes back as one JSON object per line:

```json
{"path":"a.txt","line":1,"text":"hello world","score":-4.000001}
```

## Prerequisites

Rust 1.98 or newer (`rust-toolchain.toml` pins it) and `cargo`. Install `rg` only if you run the bench parity harnesses.

## Features

- Ranked top-k results; on plain literals, the match set equals ripgrep's exactly.
- Trigram index in binary (`.bin`) or JSON format.
- Top-k early exit never displaces a true top-k hit.
- `nkg serve` holds the index in memory; `--use-index` falls back to a cold load when no daemon answers.
- JSON Lines or text output, color, and before/after context flags.

## Performance

| query | nkg | ripgrep | ugrep | zoekt |
| --- | --- | --- | --- | --- |
| `TODO_FIXME_ALPHA` | **3.9 ms** | 8.0 ms | 12.6 ms | 29.3 ms |
| `needle_1\|needle_2\|needle_3` | **3.5 ms** | 7.7 ms | 10.3 ms | 34.0 ms |
| `fn parse_config` | **3.3 ms** | 7.7 ms | 10.7 ms | 32.9 ms |
| ~~`config` (51,410 hits)~~ | withdrawn | — | — | — |

**Lower is better.** Each timing is one whole CLI invocation — process spawn, index load, search and output — against a prebuilt index. Every indexed contender is measured on its indexed path — index against index — and every match set is gated equal to ripgrep's before it is timed. Ripgrep is the scan baseline; it has no index. One run on one 32-core host; reproduce with `python3 bench/race.py`.

The index is 2.3 MB, against zoekt's 22.7 MB and ugrep's 3.1 MB.

The `config` row is withdrawn, not lost: two measurements of it disagreed on the same host and the cause is unresolved.

`tgrep` is absent from that run: the harness passed it a flag it rejects, which is fixed but not yet re-run. A fourth query matching all 51,410 lines is also omitted — two measurements of it disagreed and the cause is unresolved.

Full numbers and method: [bench/README.md](bench/README.md).

## Development

Pinned toolchain: Rust 1.98 (`rust-toolchain.toml`). `cargo test` runs 85 tests: 53 unit + 32 oracle.

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

CI runs the same four commands plus a markdown-only-README policy check.

## Learn More

- Bench (`bench/README.md`) — full numbers, corpora, and how to re-run everything.
- Man (`man/nkg.1`) — every flag, exit code, and example.
- Completions (`completions/`) — shell setup for bash, zsh, and fish.
- Src (`src/README.md`) — architecture and extension points.
- Tests (`tests/README.md`) — match-set equality contract and fixtures.

## License

Apache-2.0 — see [LICENSE](LICENSE).
