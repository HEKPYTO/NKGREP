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

## Performance

Same-machine medians after one warmup, every match set identical to
ripgrep's — read it off the chart:

![benchmark](bench/benchmark.png)

The bar to clear lives in `bench/bench_index.py`: gate A (indexed
matches ripgrep exactly), gate B (the index pays for itself on
selective queries), gate C (top-20 answers no slower than a ripgrep
full run).

## Learn More

- `bench/README.md` — full numbers, corpora, and how to re-run everything.
- `man/nkg.1` — every flag, exit code, and example (`man -l man/nkg.1`).

## License

Apache-2.0 — see [LICENSE](LICENSE).
