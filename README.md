# NKGREP

 Top-n,k ranked code search. A trigram index finds candidate files, best-first
 verify ranks them; on covered query classes (plain literals, see
 `tests/oracle.rs`) every result set is proven equal to ripgrep. n,k is the
 whole pitch: the k best answers with proof, in milliseconds.

Measured on 3,000 files, medians. Selective queries: nkgrep serve 3.9–5.0 ms
vs tgrep 7.6–9.4 ms vs ripgrep 27.4–29.4 ms. Heavy 51k-match query: ugrep
39.9 ms, ripgrep 56.4 ms, nkgrep serve 66.9 ms full dump, 35.3 ms top-20
 ranked. Nobody wins both cells; nkgrep holds selective plus ranked top-k
 with match sets equal to ripgrep on those covered classes. See `bench/`
 for the benchmarks.

## Quickstart

```bash
cargo build --release
./target/release/nkgrep index . --index nkgrep.idx.json
./target/release/nkgrep serve --index nkgrep.idx.json --port 17632 &
./target/release/nkgrep --port 17632 --top 20 -- 'pattern'
```

One-shot search without a server: `./target/release/nkgrep [--top N] -- 'pattern' <path>`.

 ## Install

 ```bash
 cargo install nkgrep
 nkgrep index . --index nkgrep.idx.json
 nkgrep serve --index nkgrep.idx.json --port 17632 &
 nkgrep --port 17632 --top 20 -- 'pattern'
 ```

 One-shot search without a server: `nkgrep [--top N] -- 'pattern' <path>`.

## Layout

- `src/main.rs` — the whole tool: walk, trigram index, rank, serve, client.
- `bench/` — corpus generator and benchmark scripts comparing against
  installed search tools.
- `tests/` — checks that indexed search returns the same results as a full
  scan on a planted fixture.

## Status

Pre-release. APIs and output formats may change before the first stable release.
