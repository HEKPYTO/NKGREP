# nkgrep

nkgrep is a ranked code search tool. Given a pattern, it returns the k
highest-scoring matches. It combines a trigram index with best-first
verification: on plain literal queries it returns exactly the match set
of ripgrep, ordered by relevance score.

## Install

```bash
cargo install nkgrep
```

Or build it yourself (crate stays `nkgrep`, the binary is `nkg`):

```bash
cargo build --release
./target/release/nkg --version
```

## Quickstart

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

## Performance

Measured on an idle Linux host, binary index, 11 interleaved rounds,
every match set identical to ripgrep's:

| query | nkg | ripgrep | |
| --- | --- | --- | --- |
| `TODO\|FIXME` | 3 ms | 8 ms | **nkg 2.7x** |
| `needle_1\|needle_2\|needle_3` | 3 ms | 8 ms | **nkg 2.7x** |
| `fn parse_config` | 3 ms | 7 ms | **nkg 2.3x** |

Full race against every indexed and scan competitor, all match
sets identical, medians of 11 interleaved rounds. Each number is one
whole CLI invocation - process spawn, index load, search and output -
against a prebuilt index, which is the honest one-shot comparison:

| query | nkg | zoekt | ugrep | tgrep |
| --- | --- | --- | --- | --- |
| `TODO_FIXME_ALPHA` | **3 ms** | 30 ms | 9 ms | 24 ms |
| `needle_1\|needle_2\|needle_3` | **3 ms** | 32 ms | 7 ms | 24 ms |
| `fn parse_config` | **3 ms** | 31 ms | 8 ms | 24 ms |

`ugrep` is measured on its **indexed** path (`ugrep-indexer` +
`ugrep --index`), not a linear scan, so this is index against index.
Fastest on 3 of 4, including 8–10x over `tgrep` and `zoekt`. `ugrep`
takes only the match-everything query, where the index rules nothing out:
its 3 ms load buys nothing and its scan runs about 1.4x `ugrep`'s.
The index is **2.3 MB against zoekt's 22.7 MB** and `ugrep`'s
3.1 MB — smaller than both for the same answers.

Most of `nkg`'s 3 ms is process spawn plus the 2.3 MB index load;
the search itself is under a millisecond. For repeated queries against
one index, `nkg serve` keeps the index resident and answers over TCP
instead of paying that load per invocation.

These margins hold on an idle host, and they depend on
host load: on a busy machine the ranking between tools changes from
round to round, so measure on a quiet box before quoting any of them.

Use the **binary** index (`--index i.bin`), not the JSON one: it is
Measured once by hand, not by any script here. The JSON
format exists for debugging.

Three gates hold that line, checked by the benchmark
harness in the repository: indexed results match ripgrep exactly, the
index pays for itself on selective queries, and top-20 is no slower
than a ripgrep full run.

## Learn More

- Bench (`bench/README.md`) — full numbers, corpora, and how to re-run everything.
- Man (`man/nkg.1`) — every flag, exit code, and example.
- Completions (`completions/`) — shell setup for bash, zsh, and fish.
- Src (`src/README.md`) — architecture and extension points.
- Tests (`tests/README.md`) — match-set equality contract and fixtures.

## License

Apache-2.0 — see [LICENSE](LICENSE).
