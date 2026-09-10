# nkg

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

Or build it yourself (crate stays `nkgrep`, the binary is `nkg`):

```bash
cargo build --release
./target/release/nkg --version
```

## 30-second quickstart

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

Pretty fast. Same-machine medians of 5 + warmup, all match sets equal to
ripgrep:

| query | nkg | tgrep |
|---|---|---|
| selective, 578 hits | 12.4 ms | 28.9 ms |
| alternation, 8,538 hits | 79.6 ms | 127.3 ms |
| heavy, top 20 | 284.4 ms | 786.8 ms |

![benchmark](bench/benchmark.png)

The gate that matters lives in `bench/bench.py`: ripgrep vs `nkg` on the
same corpus, same queries. It checks the match sets are identical
(`EQUALITY: PASS`), that `nkg` is at or under ripgrep on every query
(`SPEED: PASS`), and only then prints `KILL: SURVIVE`. Anything else is
`KILL` — no excuses.

## Learn more

- `bench/README.md` — full numbers, corpora, and how to re-run everything.
- `man/nkg.1` — every flag, exit code, and example (`man -l man/nkg.1`).
