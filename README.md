# nkgrep

nkgrep is ranked code search for people who live in big repos. You type
a pattern, it hands back the k best hits with a score attached — usually
before you've lifted your finger off enter.

Under the hood it's a trigram index plus best-first checking. On plain
literal queries it returns exactly the same matches as ripgrep, just ranked
so the good stuff floats to the top.

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
# index the repo once
nkg index . --index .nkg.json

# serve it in the background
nkg serve --index .nkg.json --port 17632 &

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

## How fast is it?

Pretty fast. From `local runs/progress.csv` (2026-09-10 `thorough` rows, every bar matched ripgrep line-for-line), medians after one warmup — 5 runs in `bench/bench.py`, 3 in the index and universe scripts:

| query | nkg hot | nkg cold | rg | tgrep | ugrep |
|---|---|---|---|---|---|
| sel-146 (~146 lines) | 4.2 ms | 6.1 ms | 29.0 ms | 6.4 ms | 22.7 ms |
| sel-86 (~86 lines) | 4.0 ms | 5.7 ms | 29.7 ms | 5.9 ms | 21.8 ms |
| sel-60 (~60 lines) | 3.7 ms | 9.4 ms | 30.1 ms | 5.7 ms | 22.0 ms |
| heavy-full (`config`) | 43.8 ms | 45.2 ms | 54.4 ms | 130.3 ms | 34.2 ms |
| heavy-top20 (`config --top 20`) | 9.7 ms | 39.8 ms | — (full 54.4 ms) | — | — |

No tgrep/ugrep top-20 rows exist in the file, so those cells stay blank — the rg full run sits next to top-20 as latency context.

![benchmark](bench/benchmark.png)

The bar to clear lives in `bench/bench_index.py`: gate A (indexed matches ripgrep exactly), gate B (the index pays for itself on selective queries), gate C (top-20 answers no slower than a ripgrep full run). `bench/bench.py` checks `nkg` against ripgrep on the same box and prints `KILL: SURVIVE` only when the sets are identical (`EQUALITY: PASS`) and `nkg` sits at or under ripgrep on every query (`SPEED: PASS`).

## Learn more

- `bench/README.md` — full numbers, corpora, and how to re-run everything.
- `man/nkg.1` — every flag, exit code, and example (`man -l man/nkg.1`).

## License

Apache-2.0 — see [LICENSE](LICENSE).
