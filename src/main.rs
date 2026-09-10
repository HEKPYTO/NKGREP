// nkgrep — ranked trigram code search.

use grep_regex::{RegexMatcher, RegexMatcherBuilder};
use grep_searcher::Searcher;
use grep_searcher::{SearcherBuilder, Sink, SinkMatch};
use ignore::WalkBuilder;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
mod prefilter;
#[derive(Serialize, Deserialize, Clone)]
#[cfg(test)]
struct Hit {
    path: std::sync::Arc<String>,
    line: u64,
    text: String,
    score: f64,
}

/// ST-5 columnar hits, borrow-banked text (cold + serve): narrow per-hit
/// record keyed by file id; match bytes are banked verbatim into a per-file
/// arena (one amortized alloc per matched file, zero per hit) and decoded
/// with the exact eager expression (`from_utf8_lossy` + char-trim) at emit,
/// where valid UTF-8 borrows and only invalid-UTF8 hits allocate — the same
/// hits that allocated before. Wire bytes stay identical.
struct HitMeta {
    line: u64,
    start: u32,
    end: u32,
    score: f64,
}

struct FileHits {
    pid: u32,
    arena: Vec<u8>,
    metas: Vec<HitMeta>,
}

struct ColCollector {
    arena: Vec<u8>,
    metas: Vec<HitMeta>,
    path_bonus: f64,
    depth_penalty: f64,
}

impl Sink for ColCollector {
    type Error = Box<dyn std::error::Error>;

    fn matched(&mut self, _searcher: &Searcher, m: &SinkMatch<'_>) -> Result<bool, Self::Error> {
        let line_no = m.line_number().unwrap_or(0);
        let bytes = m.bytes();
        let score = self.path_bonus - self.depth_penalty - (line_no as f64) / 1e6;
        let start = self.arena.len() as u32;
        self.arena.extend_from_slice(bytes);
        let end = self.arena.len() as u32;
        self.metas.push(HitMeta { line: line_no, start, end, score });
        Ok(true)
    }
}

/// Columnar verify: same TLS Searcher + 64 KB buffer + search_slice core as
/// the serve-side cached verify, but the sink banks verbatim match bytes.
fn verify_one_raw(pid: u32, path: &str, matcher: &RegexMatcher, file_score: f64) -> Option<FileHits> {
    use std::cell::RefCell;
    thread_local! {
        static SEARCHER: RefCell<Searcher> = RefCell::new(SearcherBuilder::new().build());
        static BUF: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(64 * 1024));
    }
    let mut sink = ColCollector {
        arena: vec![],
        metas: vec![],
        path_bonus: file_score,
        depth_penalty: 0.0,
    };
    // `with` (not try_with): destroyed-TLS fallback returning empty would
    // silently drop matches and break the oracle; loud panic is correct.
    // Any IO/search error still discards partial hits, as before.
    let ok = SEARCHER.with(|s| {
        BUF.with(|b| {
            let mut buf = b.borrow_mut();
            buf.clear();
            let mut searcher = s.borrow_mut();
            (|| -> std::io::Result<bool> {
                use std::io::Read;
                std::fs::File::open(path)?.read_to_end(&mut buf)?;
                // Per-file early exit: an empty file holds no lines and no
                // matches; skip searcher setup. Result identical to searching
                // (Ok with zero banked hits).
                if buf.is_empty() {
                    return Ok(true);
                }
                Ok(searcher.search_slice(matcher, &buf, &mut sink).is_ok())
            })()
            .unwrap_or(false)
        })
    });
    if ok && !sink.metas.is_empty() { Some(FileHits { pid, arena: sink.arena, metas: sink.metas }) } else { None }
}
/// Serve-side columnar verify: same TLS Searcher + 64 KB buffer +
/// search_slice core and verbatim-banked sink as `verify_one_raw`, but the
/// file bytes come through the daemon fd cache (`read_verify_bytes`).
#[derive(Serialize, Deserialize)]
struct Index {
    /// Canonical absolute path of the tree the index was built from.
    /// Required: old absolute-path indexes without it fail to parse and are
    /// rejected loudly at load (rebuild with `nkgrep index`).
    root: String,
    /// (device, inode) cookie of the build root; 0/0 where unavailable.
    /// Catches a replaced tree behind an unchanged path.
    root_dev: u64,
    root_ino: u64,
    /// Root-relative paths (to be joined with the query root at load).
    files: Vec<String>,
    /// Packed trigram keys: gram_pack([a,b,c]) = (a<<16)|(b<<8)|c.
    /// Bijective over the 3-byte domain (top byte always zero); no lossy
    /// UTF-8 string round trip, 4 B fixed keys in the binary codec.
    postings: HashMap<u32, Vec<u32>>,
}

/// Canonical absolute fingerprint of a build/query root; exit 2 when the
/// root does not resolve.
fn walk_files(root: &PathBuf) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = vec![];
    for entry in WalkBuilder::new(root)
        .hidden(true)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .parents(true)
        .require_git(true)
        .build()
    {
        match entry {
            Ok(e) => {
                if e.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    paths.push(e.path().to_path_buf());
                }
            }
            Err(e) => eprintln!("nkgrep: walk error: {e}"),
        }
    }
    paths
}

fn trigrams_of(bytes: &[u8]) -> HashSet<[u8; 3]> {
    let mut set = HashSet::new();
    for w in bytes.windows(3) {
        set.insert([w[0], w[1], w[2]]);
    }
    set
}

/// Bijective trigram pack: (a<<16)|(b<<8)|c. Numeric order equals
/// lexicographic byte order, so sorted keys stay byte-stable across the
/// format rev. Top byte always zero; unpack is (k>>16, k>>8, k) & 0xFF.
fn gram_pack(g: &[u8; 3]) -> u32 {
    ((g[0] as u32) << 16) | ((g[1] as u32) << 8) | (g[2] as u32)
}

/// Regex-aware literal extraction: split into alternation branches on `|`
/// that is neither escaped nor inside a `[...]` class; per branch, runs of
/// [A-Za-z0-9_] len>=3 give required trigrams. Group depth is ignored on
/// purpose: `(a|b)` still alternates, so its `|` separates branches, and
/// each branch's grams remain a subset of its match text, keeping the union
/// a superset of all matches. Escapes (`\x`) never contribute a literal
/// (covers `\|`, `\d`, `\n`, `\\`); class contents contribute nothing.
/// None = no usable literal in some branch, caller must full-scan.
fn cmd_index(root: &PathBuf, idx_path: &str) {
    let t0 = Instant::now();
    let root_canon = canon_root(root);
    let (root_dev, root_ino) = root_cookie(&root_canon);
    let root_fp = root_canon.to_string_lossy().into_owned();
    let paths = walk_files(root);
    let entries: Vec<(String, HashSet<[u8; 3]>)> = paths
        .par_iter()
        .filter_map(|p| {
            let bytes = std::fs::read(p).ok()?;
            if bytes.iter().take(8192).any(|&b| b == 0) {
                return None;
            }
            // Root-relative entry: canonicalize both sides so symlinked
            // roots (e.g. /tmp on macOS) fingerprint stably. Files escaping
            // the root via symlink are skipped, never stored absolute.
            let rel = std::fs::canonicalize(p)
                .ok()?
                .strip_prefix(&root_canon)
                .ok()?
                .to_string_lossy()
                .into_owned();
            Some((rel, trigrams_of(&bytes)))
        })
        .collect();
    let mut files = Vec::with_capacity(entries.len());
    let mut postings: HashMap<u32, Vec<u32>> = HashMap::new();
    for (path, grams) in &entries {
        let id = files.len() as u32;
        files.push(path.clone());
        for g in grams {
            postings.entry(gram_pack(g)).or_default().push(id);
        }
    }
    let idx = Index {
        root: root_fp,
        root_dev,
        root_ino,
        files,
        postings,
    };
    if idx_path.ends_with(".bin") {
        std::fs::write(idx_path, encode_index_bin(&idx)).unwrap();
    } else {
        std::fs::write(idx_path, serde_json::to_string(&idx).unwrap()).unwrap();
    }
    eprintln!(
        "nkgrep: indexed {} files in {} ms -> {idx_path}",
        entries.len(),
        t0.elapsed().as_millis()
    );
}

/// O3 daemon fd cache (hot-serve ONLY; the cold path never sees it): warm
/// file fds held for the daemon lifetime, keyed by file id. Hit contract:
/// the live path's (len, mtime) must equal the cached fd's own (len, mtime)
/// on every use, else the entry is reopened — an edit between queries is
/// never served stale. A replacement between the stat and the pread reads
/// old-or-new atomically per fd, never corrupt; a pread that loses its fd
/// to a concurrent replace retries once, then fails like any IO error.
/// Any metadata/open failure falls back to plain open+read, so the cache
/// never fails where the uncached path succeeds.
fn ranked_candidates(idx: &Index, pattern: &str) -> Option<Vec<(u32, f64)>> {
    let ors = query_grams(pattern)?;
    let n = idx.files.len() as f64;
    // (postings, idf weight) per gram occurrence, in query order, for
    // deferred exact scoring of survivors only.
    let mut occ: Vec<(&[u32], f64)> = vec![];
    let mut cand: Vec<u32> = vec![];
    let mut tmp: Vec<u32> = vec![];
    for ands in &ors {
        let mut lists: Vec<&[u32]> = Vec::with_capacity(ands.len());
        let mut empty = false;
        for g in ands {
            match idx.postings.get(g) {
                None => {
                    empty = true;
                    break;
                }
                Some(list) => {
                    occ.push((list.as_slice(), (n / list.len() as f64).ln()));
                    lists.push(list.as_slice());
                }
            }
        }
        if empty || lists.is_empty() {
            continue;
        }
        let branch = prefilter::intersect_all(&mut lists);
        prefilter::union_sorted_into(&cand, &branch, &mut tmp);
        std::mem::swap(&mut cand, &mut tmp);
    }
    let mut is_cand = vec![false; idx.files.len()];
    for &id in &cand {
        is_cand[id as usize] = true;
    }
    let mut scores = vec![0.0f64; idx.files.len()];
    for &(list, w) in &occ {
        for &id in list {
            if is_cand[id as usize] {
                scores[id as usize] += w;
            }
        }
    }
    let mut order: Vec<(u32, f64)> = cand
        .into_iter()
        .map(|id| {
            let p = &idx.files[id as usize];
            let depth = PathBuf::from(p).components().count() as f64;
            let bonus = if p.contains(pattern) { 100.0 } else { 0.0 };
            (id, scores[id as usize] + bonus - depth)
        })
        .collect();
    order.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Some(order)
}

/// Rank order over a standalone scores vec (ST-5 columnar sort): indices
/// only, comparator verbatim the Hit-order one (NaN fallback included), so
/// the order — ties included — matches the stable fat-Hit sort given the
/// same collect sequence. Sort traffic touches 8 B scores, never payloads.
fn usage() -> ! {
    eprintln!("usage: nkgrep index <path> [--index FILE]");
    eprintln!("       nkgrep serve --index FILE --port PORT");
    eprintln!("       nkgrep [--top N] [--use-index FILE | --port PORT] [--] <pattern> [path]");
    std::process::exit(2);
}

fn main() {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.first().map(|s| s.as_str()) == Some("index") {
        if raw.len() < 2 {
            usage();
        }
        let root = PathBuf::from(&raw[1]);
        let mut idx = String::from(".nkgrep.json");
        let mut j = 2;
        while j < raw.len() {
            if raw[j] == "--index" {
                j += 1;
                if j >= raw.len() {
                    usage();
                }
                idx = raw[j].clone();
            }
            j += 1;
        }
        cmd_index(&root, &idx);
        return;
    }
    if raw.first().map(|s| s.as_str()) == Some("serve") {
        let mut idx = String::from(".nkgrep.json");
        let mut port: u16 = 0;
        let mut j = 1;
        while j < raw.len() {
            if raw[j] == "--index" {
                j += 1;
                if j >= raw.len() {
                    usage();
                }
                idx = raw[j].clone();
            } else if raw[j] == "--port" {
                j += 1;
                if j >= raw.len() {
                    usage();
                }
                port = raw[j].parse().unwrap_or(0);
                if port == 0 {
                    usage();
                }
            }
            j += 1;
        }
        cmd_serve(&idx, port);
        return;
    }
    let mut top: Option<usize> = None;
    let mut use_index: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut pos: Vec<String> = vec![];
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == "--" {
            i += 1;
            continue;
        }
        if raw[i] == "--top" {
            i += 1;
            if i >= raw.len() {
                usage();
            }
            top = raw[i].parse().ok();
            if top.is_none() {
                usage();
            }
        } else if raw[i] == "--use-index" {
            i += 1;
            if i >= raw.len() {
                usage();
            }
            use_index = Some(raw[i].clone());
        } else if raw[i] == "--port" {
            i += 1;
            if i >= raw.len() {
                usage();
            }
            port = raw[i].parse().ok();
            if port.is_none() {
                usage();
            }
        } else {
            pos.push(raw[i].clone());
        }
        i += 1;
    }
    if pos.is_empty() || pos.len() > 2 {
        usage();
    }
    if port.is_none() && pos.len() != 2 {
        usage();
    }
    let pattern = pos[0].clone();
    let root = PathBuf::from(pos.get(1).map(|s| s.as_str()).unwrap_or("."));

    let t0 = Instant::now();
    if port.is_none() {
        if let Some(idx_path) = &use_index {
            if let Some((raw, matches)) = try_serve_query(idx_path, &pattern, top) {
                let stdout = std::io::stdout();
                let mut writer = std::io::BufWriter::with_capacity(1024 * 1024, stdout.lock());
                writer.write_all(&raw).unwrap();
                writer.flush().unwrap();
                eprintln!(
                    "nkgrep: {matches} matches via serve, {} ms",
                    t0.elapsed().as_millis()
                );
                if matches == 0 {
                    std::process::exit(1);
                }
                return;
            }
            eprintln!("nkgrep: server unreachable, falling back to local index");
        }
    }
    if let Some(p) = port {
        let (raw, matches) = client_query(p, &pattern, top);
        let stdout = std::io::stdout();
        let mut writer = std::io::BufWriter::with_capacity(1024 * 1024, stdout.lock());
        writer.write_all(&raw).unwrap();
        writer.flush().unwrap();
        eprintln!(
            "nkgrep: {matches} matches via serve, {} ms",
            t0.elapsed().as_millis()
        );
        if matches == 0 {
            std::process::exit(1);
        }
        return;
    }

    let matcher = match build_matcher(&pattern) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("nkgrep: bad regex: {e}");
            std::process::exit(2);
        }
    };
    // ST-5 columnar cold path: borrow-banked FileHits (pid = file id when
    // indexed, ptab index on scan) + flattened side scores vec + pid-indexed
    // escaped paths. Serve emits the same banked path; the oracle pins both
    // byte-identical.
    let mut hits: Vec<FileHits> = vec![];
    let mut ptab: Vec<String> = vec![];
    let mut hits_indexed = false;
    let files: usize;
    let mut load_ms = 0u128;
    let idx_opt: Option<Index> = if let Some(idx_path) = &use_index {
        let t_load = Instant::now();
        let idx = load_index_for_query(idx_path, &root);
        load_ms = t_load.elapsed().as_millis();
        Some(idx)
    } else {
        None
    };
    if let Some(idx) = &idx_opt {
        let n = idx.files.len() as f64;
        let mut scores = vec![0.0f64; idx.files.len()];
        let mut order: Vec<u32> = vec![];
        let mut fallback = false;
        match query_grams(&pattern) {
            None => fallback = true,
            Some(ors) => {
                let mut occ: Vec<(&[u32], f64)> = vec![];
                let mut cand: Vec<u32> = vec![];
                let mut tmp: Vec<u32> = vec![];
                for ands in &ors {
                    let mut lists: Vec<&[u32]> = Vec::with_capacity(ands.len());
                    let mut empty = false;
                    for g in ands {
                        match idx.postings.get(g) {
                            None => {
                                empty = true;
                                break;
                            }
                            Some(list) => {
                                occ.push((list.as_slice(), (n / list.len() as f64).ln()));
                                lists.push(list.as_slice());
                            }
                        }
                    }
                    if empty || lists.is_empty() {
                        continue;
                    }
                    let branch = prefilter::intersect_all(&mut lists);
                    prefilter::union_sorted_into(&cand, &branch, &mut tmp);
                    std::mem::swap(&mut cand, &mut tmp);
                }
                let mut is_cand = vec![false; idx.files.len()];
                for &id in &cand {
                    is_cand[id as usize] = true;
                }
                for &(list, w) in &occ {
                    for &id in list {
                        if is_cand[id as usize] {
                            scores[id as usize] += w;
                        }
                    }
                }
                order = cand;
            }
        }
        if fallback {
            eprintln!("nkgrep: no usable literal, falling back to scan");
            let paths = walk_files(&root);
            files = paths.len();
            ptab = paths
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect();
            hits = (0u32..ptab.len() as u32)
                .into_par_iter()
                .filter_map(|pid| verify_one_raw(pid, &ptab[pid as usize], &matcher, 0.0))
                .collect();
        } else {
            for id in order.iter() {
                let p = &idx.files[*id as usize];
                let depth = PathBuf::from(p).components().count() as f64;
                let bonus = if p.contains(pattern.as_str()) { 100.0 } else { 0.0 };
                scores[*id as usize] += bonus - depth;
            }
            order.sort_by(|a, b| {
                scores[*b as usize]
                    .partial_cmp(&scores[*a as usize])
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            files = order.len();
            // Rank-ordered parallel verify, kth early exit between batches
            // (spec §6: match score ≤ file score, exit moves only with proof).
            hits = parallel_verify_batched_raw(idx, &matcher, &order, &scores, top);
            hits_indexed = true;
        }
    } else {
        let paths = walk_files(&root);
        files = paths.len();
        ptab = paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        hits = (0u32..ptab.len() as u32)
            .into_par_iter()
            .filter_map(|pid| {
                // Same verify core as the indexed path: the depth penalty
                // folds into the score (the raw sink's depth_penalty stays 0),
                // so scores are identical to the old inline Collector
                // with its per-file Searcher + per-file matcher clone.
                let ps = &ptab[pid as usize];
                let depth = PathBuf::from(ps).components().count() as f64;
                let bonus = if ps.contains(pattern.as_str()) {
                    100.0
                } else {
                    0.0
                };
                verify_one_raw(pid, ps, &matcher, bonus - depth)
            })
            .collect();
    }
    // Columnar sort: flattened side scores vec drives index order; comparator
    // verbatim the fat-Hit one, so rank (ties included) is unchanged.
    // `loc` maps each flat position to (file, meta) for banked decode.
    let (hit_scores, loc) = flat_scores(&hits);
    let mut ord = raw_order(&hit_scores);
    if let Some(n) = top {
        ord.truncate(n);
    }
    let matches = ord.len();
    // Ordered parallel emission (cold emission only): manual memchr escaper
    // into chunk buffers per-thread, join in order, single sequential write.
    // Serial fallback under threshold keeps selective/small queries off the
    // rayon ramp. serde_json remains the differential oracle in tests.
    // Each unique path is escaped once per query (heavy-full emits 51k hits
    // from ~3k files) into a pid-indexed table: no per-hit HashMap, no Arc.
    // Indexed pids address the index file table, scan pids the ptab.
    // Hit text decodes from the file arena at emit (`banked_text`): valid
    // UTF-8 borrows, so the common path allocates nothing per hit.
    const EMIT_PAR_MIN: usize = 4000;
    const EMIT_CHUNK: usize = 4096;
    let table_len = match &idx_opt {
        Some(idx) if hits_indexed => idx.files.len(),
        _ => ptab.len(),
    };
    let mut esc: Vec<Option<Vec<u8>>> = vec![None; table_len];
    for &i in &ord {
        let (fi, _) = loc[i as usize];
        let pid = hits[fi as usize].pid as usize;
        if esc[pid].is_none() {
            let ps: &str = match &idx_opt {
                Some(idx) if hits_indexed => &idx.files[pid],
                _ => &ptab[pid],
            };
            let mut v = Vec::with_capacity(ps.len() + 2);
            push_escaped_json(&mut v, ps);
            esc[pid] = Some(v);
        }
    }
    // Emit one line per ordered hit; sequential and chunked-parallel share
    // this body so both stay byte-identical.
    let emit_one = |buf: &mut Vec<u8>, fh: &FileHits, m: &HitMeta, esc: &[Option<Vec<u8>>]| {
        let text = banked_text(fh, m);
        emit_raw_with_path(buf, esc[fh.pid as usize].as_ref().unwrap(), m.line, &text, m.score);
    };
    let stdout = std::io::stdout();
    let mut writer = std::io::BufWriter::with_capacity(1024 * 1024, stdout.lock());
    if ord.len() < EMIT_PAR_MIN {
        let mut buf = Vec::with_capacity(ord.len() * 160);
        for &i in &ord {
            let (fi, mi) = loc[i as usize];
            let fh = &hits[fi as usize];
            emit_one(&mut buf, fh, &fh.metas[mi as usize], &esc);
        }
        writer.write_all(&buf).unwrap();
    } else {
        let parts: Vec<Vec<u8>> = ord
            .par_chunks(EMIT_CHUNK)
            .map(|chunk| {
                let mut buf = Vec::with_capacity(chunk.len() * 160);
                for &i in chunk {
                    let (fi, mi) = loc[i as usize];
                    // `hits`/`esc` are shared read-only across the wave; each
                    // chunk writes only its own buffer, joined in order below.
                    let fh: &FileHits = &hits[fi as usize];
                    let text = banked_text(fh, &fh.metas[mi as usize]);
                    emit_raw_with_path(&mut buf, esc[fh.pid as usize].as_ref().unwrap(), fh.metas[mi as usize].line, &text, fh.metas[mi as usize].score);
                }
                buf
            })
            .collect();
        for part in &parts {
            writer.write_all(part).unwrap();
        }
    }
    writer.flush().unwrap();
    eprintln!(
        "nkgrep: {matches} matches in {files} files, {} ms (index load {load_ms} ms)",
        t0.elapsed().as_millis()
    );
    if matches == 0 {
        std::process::exit(1);
    }
}

#[cfg(test)]
