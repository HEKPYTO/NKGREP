# nkgrep

Ranked code search for people who live in big repos. You type a pattern, it
hands back the k best hits with a score attached — usually before you've
lifted your finger off enter.

Under the hood it's a trigram index plus best-first checking. On plain
literal queries it returns exactly the same matches as ripgrep, just ranked
so the good stuff floats to the top.

## Install

```bash
cargo install nkgrep
```

Or build it yourself:

```bash
cargo build --release
./target/release/nkgrep --version
```

## 30-second quickstart

```bash
# index the repo once
nkgrep index . --index nkgrep.idx.json

# serve it in the background
nkgrep serve --index nkgrep.idx.json --port 17632 &

# ask for the 20 best hits
nkgrep --port 17632 --top 20 -- 'TODO|FIXME'
```

No server? No problem — plain one-shot search works too:

```bash
nkgrep -- 'pattern' src
```

Each hit comes back as one JSON object per line:

```json
{"path":"a.txt","line":1,"text":"hello world","score":-4.000001}
```

## How fast is it?

Pretty fast. Same-machine medians of 5 + warmup, all match sets equal to
ripgrep:

| query | nkgrep | tgrep |
|---|---|---|
| selective, 578 hits | 12.4 ms | 28.9 ms |
| alternation, 8,538 hits | 79.6 ms | 127.3 ms |
| heavy, top 20 | 284.4 ms | 786.8 ms |

![benchmark](bench/benchmark.png)

## Learn more

- `bench/README.md` — full numbers, corpora, and how to re-run everything.
- `man/nkgrep.1` — every flag, exit code, and example (`man -l man/nkgrep.1`).
