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
    // silently drop matches and break the equality; loud panic is correct.
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
fn verify_one_raw_cached(
    pid: u32,
    path: &str,
    matcher: &RegexMatcher,
    file_score: f64,
    fdc: Option<(&FdCache, u32)>,
) -> Option<FileHits> {
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
    // silently drop matches and break the equality; loud panic is correct.
    // Any IO/search error still discards partial hits, as before.
    let ok = SEARCHER.with(|s| {
        BUF.with(|b| {
            let mut buf = b.borrow_mut();
            buf.clear();
            let mut searcher = s.borrow_mut();
            (|| -> std::io::Result<bool> {
                read_verify_bytes(fdc, path, &mut buf, false)?;
                // Twin of the `verify_one_raw` early exit: empty files hold
                // no matches; skip searcher setup identically.
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
fn canon_root(root: &std::path::Path) -> PathBuf {
    match std::fs::canonicalize(root) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("nkgrep: bad root {}: {e}", root.display());
            std::process::exit(2);
        }
    }
}

/// Stable (device, inode) cookie for a canonical root; (0, 0) where the
/// platform offers no file identity (non-unix) or metadata is unreadable.
/// Unlike mtime this never changes when files are added inside the tree.
fn root_cookie(canon: &std::path::Path) -> (u64, u64) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match std::fs::metadata(canon) {
            Ok(m) => (m.dev(), m.ino()),
            Err(_) => (0, 0),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = canon;
        (0, 0)
    }
}

/// Parse index JSON; old absolute-path indexes (missing `root`) and corrupt
/// files are refused loudly instead of silently matching nothing.
fn parse_index(idx_path: &str, data: &str) -> Index {
    match serde_json::from_str::<Index>(data) {
        Ok(idx) => {
            if idx.files.iter().any(|p| PathBuf::from(p).is_absolute()) {
                eprintln!("nkgrep: stale absolute-path index {idx_path}: rebuild with `nkgrep index`");
                std::process::exit(2);
            }
            idx
        }
        Err(e) => {
            eprintln!("nkgrep: unreadable index {idx_path} (old format? rebuild with `nkgrep index`): {e}");
            std::process::exit(2);
        }
    }
}
/// Binary index magic (8 B) + plain-LE linear layout, no codec (NKGREP02):
/// magic | root_dev u64 | root_ino u64 | root_len u32 + root bytes
/// | nfiles u32 + (len u32 + bytes)* | npostings u32 + (key u32 + vlen u32 + ids u32 LE)*.
/// Keys are packed trigrams (gram_pack), sorted numeric on write for stable
/// bytes. Any truncation → loud exit 2. NKGREP01 (u64 widths + String keys)
/// is refused loudly as a stale format, same as a fingerprint mismatch.
const BIN_MAGIC: &[u8; 8] = b"NKGREP02";
const OLD_BIN_MAGIC: &[u8; 8] = b"NKGREP01";

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn encode_index_bin(idx: &Index) -> Vec<u8> {
    let mut out = Vec::with_capacity(idx.files.len() * 40);
    out.extend_from_slice(BIN_MAGIC);
    put_u64(&mut out, idx.root_dev);
    put_u64(&mut out, idx.root_ino);
    put_u32(&mut out, idx.root.len() as u32);
    out.extend_from_slice(idx.root.as_bytes());
    put_u32(&mut out, idx.files.len() as u32);
    for f in &idx.files {
        put_u32(&mut out, f.len() as u32);
        out.extend_from_slice(f.as_bytes());
    }
    let mut keys: Vec<u32> = idx.postings.keys().copied().collect();
    keys.sort();
    put_u32(&mut out, keys.len() as u32);
    for k in keys {
        let ids = &idx.postings[&k];
        put_u32(&mut out, k);
        put_u32(&mut out, ids.len() as u32);
        for id in ids {
            out.extend_from_slice(&id.to_le_bytes());
        }
    }
    out
}

fn parse_index_bin(idx_path: &str, data: &[u8]) -> Index {
    let refuse = |why: &str| -> ! {
        eprintln!("nkgrep: unreadable index {idx_path} (truncated binary? rebuild with `nkgrep index`): {why}");
        std::process::exit(2);
    };
    let mut cur = BIN_MAGIC.len();
    let take = |cur: &mut usize, n: usize| -> &[u8] {
        let end = cur.checked_add(n).unwrap_or(usize::MAX);
        if end > data.len() {
            refuse("unexpected end of file");
        }
        let s = &data[*cur..end];
        *cur = end;
        s
    };
    let u64_at = |cur: &mut usize| -> u64 {
        let b = take(cur, 8);
        u64::from_le_bytes(b.try_into().unwrap())
    };
    let u32_at = |cur: &mut usize| -> u32 {
        let b = take(cur, 4);
        u32::from_le_bytes(b.try_into().unwrap())
    };
    let str_at = |cur: &mut usize| -> String {
        let n = u32_at(cur) as usize;
        if n > data.len() {
            refuse("bad length prefix");
        }
        match std::str::from_utf8(take(cur, n)) {
            Ok(s) => s.to_owned(),
            Err(_) => refuse("non-utf8 path"),
        }
    };
    let root_dev = u64_at(&mut cur);
    let root_ino = u64_at(&mut cur);
    let root = str_at(&mut cur);
    let nfiles = u32_at(&mut cur) as usize;
    if nfiles > data.len() {
        refuse("bad file count");
    }
    let mut files = Vec::with_capacity(nfiles.min(1 << 20));
    for _ in 0..nfiles {
        files.push(str_at(&mut cur));
    }
    let npost = u32_at(&mut cur) as usize;
    if npost > data.len() {
        refuse("bad posting count");
    }
    let mut postings = HashMap::with_capacity(npost.min(1 << 20));
    for _ in 0..npost {
        let k = u32_at(&mut cur);
        // No vlen-vs-nfiles cap: distinct byte triples share no key now,
        // but one file still pushes its id once per key while vlen counts
        // ids, not files. Per-id range checks below still reject corruption.
        let vlen = u32_at(&mut cur) as usize;
        let raw = take(&mut cur, vlen.saturating_mul(4));
        if raw.len() != vlen * 4 {
            refuse("bad posting length");
        }
        let mut ids = Vec::with_capacity(vlen);
        for c in raw.chunks_exact(4) {
            let id = u32::from_le_bytes(c.try_into().unwrap());
            if id as usize >= nfiles {
                refuse("posting id out of range");
            }
            ids.push(id);
        }
        postings.insert(k, ids);
    }
    let idx = Index { root, root_dev, root_ino, files, postings };
    if idx.files.iter().any(|p| PathBuf::from(p).is_absolute()) {
        eprintln!("nkgrep: stale absolute-path index {idx_path}: rebuild with `nkgrep index`");
        std::process::exit(2);
    }
    idx
}

/// Read raw index bytes once; binary (magic) vs JSON dispatch lives here so
/// both load helpers share it with unchanged signatures.
fn read_index_bytes(idx_path: &str) -> Vec<u8> {
    match std::fs::read(idx_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("nkgrep: cannot read index {idx_path}: {e}");
            std::process::exit(2);
        }
    }
}
fn parse_index_auto(idx_path: &str, data: &[u8]) -> Index {
    if data.starts_with(BIN_MAGIC) {
        return parse_index_bin(idx_path, data);
    }
    if data.starts_with(OLD_BIN_MAGIC) || data.starts_with(b"NKGREP") {
        eprintln!("nkgrep: stale index format {idx_path} (expected NKGREP02): rebuild with `nkgrep index`");
        std::process::exit(2);
    }
    match std::str::from_utf8(data) {
        Ok(s) => parse_index(idx_path, s),
        Err(e) => {
            eprintln!("nkgrep: unreadable index {idx_path} (old format? rebuild with `nkgrep index`): {e}");
            std::process::exit(2);
        }
    }
}
/// Load an index for a query rooted at `query_root`: refuse (exit 2) on
/// fingerprint mismatch, then materialize root-relative entries to
/// query-root-joined paths so rank/verify see scan-identical strings.
fn load_index_for_query(idx_path: &str, query_root: &PathBuf) -> Index {
    let data = read_index_bytes(idx_path);
    let mut idx = parse_index_auto(idx_path, &data);
    let q_canon = canon_root(query_root);
    if q_canon.to_string_lossy() != idx.root {
        eprintln!(
            "nkgrep: index root mismatch (built at {}, queried at {})",
            idx.root,
            q_canon.display()
        );
    }
    let (dev, ino) = root_cookie(&q_canon);
    if idx.root_dev != 0 && (dev, ino) != (idx.root_dev, idx.root_ino) {
        eprintln!(
            "nkgrep: index root mismatch (built at {}, queried at {}: root replaced)",
            idx.root,
            q_canon.display()
        );
        std::process::exit(2);
    }
    for f in idx.files.iter_mut() {
        *f = query_root.join(&*f).to_string_lossy().into_owned();
    }
    idx
}

/// Load an index for `serve`: no query root exists, so the stored canonical
/// root is the verify base. Refuse (exit 2) when the tree moved or was
/// replaced behind the stored fingerprint.
fn load_index_for_serve(idx_path: &str) -> Index {
    let data = read_index_bytes(idx_path);
    let mut idx = parse_index_auto(idx_path, &data);
    let base = PathBuf::from(&idx.root);
    let live = canon_root(&base);
    let (dev, ino) = root_cookie(&live);
    if live.to_string_lossy() != idx.root
        || (idx.root_dev != 0 && (dev, ino) != (idx.root_dev, idx.root_ino))
    {
        eprintln!(
            "nkgrep: index root mismatch (built at {}, now at {})",
            idx.root,
            live.display()
        );
        std::process::exit(2);
    }
    for f in idx.files.iter_mut() {
        *f = base.join(&*f).to_string_lossy().into_owned();
    }
    idx
}

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
fn query_grams(pattern: &str) -> Option<Vec<Vec<u32>>> {
    let mut ors = vec![];
    for branch in split_branches(pattern) {
        let mut ands = HashSet::new();
        for run in literal_runs(&branch) {
            if run.len() >= 3 {
                for w in run.windows(3) {
                    ands.insert(gram_pack(&[w[0], w[1], w[2]]));
                }
            }
        }
        if ands.is_empty() {
            return None;
        }
        let mut grams = ands.into_iter().collect::<Vec<_>>();
        grams.sort();
        ors.push(grams);
    }
    Some(ors)
}

/// Split on unescaped `|` outside `[...]` classes. Verbatim copy otherwise
/// (escapes and classes preserved for `literal_runs` to interpret).
fn split_branches(pattern: &str) -> Vec<String> {
    let mut out: Vec<String> = vec![String::new()];
    let mut it = pattern.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\\' => {
                out.last_mut().unwrap().push('\\');
                if let Some(e) = it.next() {
                    out.last_mut().unwrap().push(e);
                }
            }
            '[' => {
                let mut cls = String::from("[");
                if it.peek() == Some(&'^') {
                    cls.push(it.next().unwrap());
                }
                if it.peek() == Some(&']') {
                    cls.push(it.next().unwrap()); // `[]...]` — first ] literal
                }
                {
                    let iter = it.by_ref();
                    while let Some(c2) = iter.next() {
                        cls.push(c2);
                        if c2 == '\\' {
                            if let Some(e) = iter.next() {
                                cls.push(e); // escaped char inside class
                            }
                            continue;
                        }
                        if c2 == ']' {
                            break;
                        }
                    }
                }
                out.last_mut().unwrap().push_str(&cls);
            }
            '|' => out.push(String::new()),
            c => out.last_mut().unwrap().push(c),
        }
    }
    out
}

/// Definitely-literal alphanumeric-underscore runs: skips `\x` escapes and
/// `[...]` class contents (an unclosed `[` swallows the rest, conservatively
/// yielding fewer grams, never wrong ones).
fn literal_runs(branch: &str) -> Vec<Vec<u8>> {
    let mut runs = vec![];
    let mut cur: Vec<u8> = vec![];
    let mut it = branch.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\\' => {
                if !cur.is_empty() {
                    runs.push(std::mem::take(&mut cur));
                }
                let _ = it.next(); // escaped char is never a literal
            }
            '[' => {
                if !cur.is_empty() {
                    runs.push(std::mem::take(&mut cur));
                }
                if it.peek() == Some(&'^') {
                    it.next();
                }
                if it.peek() == Some(&']') {
                    it.next();
                }
                let mut esc = false;
                for c2 in it.by_ref() {
                    if esc {
                        esc = false;
                        continue;
                    }
                    if c2 == '\\' {
                        esc = true;
                        continue;
                    }
                    if c2 == ']' {
                        break;
                    }
                }
            }
            c if c.is_ascii_alphanumeric() || c == '_' => cur.push(c as u8),
            _ => {
                if !cur.is_empty() {
                    runs.push(std::mem::take(&mut cur));
                }
            }
        }
    }
    if !cur.is_empty() {
        runs.push(cur);
    }
    runs
}

/// ASCII-gated matcher construction (V1): when the pattern is ASCII, skip the
/// Unicode tables (`unicode(false)` + `\n` line terminator, which unlocks the
/// fast line-oriented search path); when it is additionally a pure literal,
/// compile with `fixed_strings`. Each flag is independent and keeps
/// independently. A builder error (e.g. the line terminator rejecting a
/// pattern that can match `\n`) retries less-gated, ending at plain
/// `RegexMatcher::new`, so construction never fails where it used to work.
fn build_matcher(pattern: &str) -> Result<RegexMatcher, grep_regex::Error> {
    let ascii_only = pattern.is_ascii();
    let literal_only = is_pure_literal(pattern);
    if ascii_only || literal_only {
        let mut b = RegexMatcherBuilder::new();
        if ascii_only {
            b.unicode(false);
            b.line_terminator(Some(b'\n'));
        }
        if literal_only {
            b.fixed_strings(true);
        }
        if let Ok(m) = b.build(pattern) {
            return Ok(m);
        }
        if ascii_only {
            let mut bz = RegexMatcherBuilder::new();
            bz.unicode(false);
            if literal_only {
                bz.fixed_strings(true);
            }
            if let Ok(m) = bz.build(pattern) {
                return Ok(m);
            }
        }
    }
    RegexMatcher::new(pattern)
}
/// Pure-literal probe for the `fixed_strings` gate: one `|`-free branch whose
/// every byte survives `literal_runs` as a single run. Conservative on
/// purpose: any metachar, escape, class, or alternation disqualifies (that
/// query keeps the regex engine, gaining only `unicode(false)` when ASCII).
fn is_pure_literal(pattern: &str) -> bool {
    if pattern.is_empty() || !pattern.is_ascii() {
        return false;
    }
    let branches = split_branches(pattern);
    if branches.len() != 1 {
        return false;
    }
    let runs = literal_runs(&branches[0]);
    runs.len() == 1 && runs[0].len() == pattern.len()
}

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
struct CachedFd {
    fd: std::os::unix::io::RawFd,
    len: u64,
    modified: std::time::SystemTime,
}

impl Drop for CachedFd {
    fn drop(&mut self) {
        // SAFETY: fd owned from `into_raw_fd` on fill, closed exactly once
        // (replace drops the old entry; daemon exit drops the slots).
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// Dense per-file slots (ids are 0..nfiles): one small mutex per file, so a
/// warm pread hit never waits on another file's open and never hashes.
struct FdCache {
    slots: Vec<std::sync::Mutex<Option<CachedFd>>>,
}

impl FdCache {
    fn new(nfiles: usize) -> Self {
        let mut slots = Vec::with_capacity(nfiles);
        for _ in 0..nfiles {
            slots.push(std::sync::Mutex::new(None));
        }
        FdCache { slots }
    }
}

/// Best-effort NOFILE bump so the daemon can hold one fd per indexed file.
/// Never fails the daemon: when the ceiling stays low the cache just fills
/// what fits and fill-open errors fall back to plain open+read.
fn bump_nofile_for_cache(want_files: usize) {
    // SAFETY: getrlimit/setrlimit with a valid stack struct; daemon tuning.
    unsafe {
        let mut lim: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim as *mut _) != 0 {
            return;
        }
        let want = (want_files as libc::rlim_t).saturating_add(128);
        if lim.rlim_cur >= want {
            return;
        }
        let mut next = lim;
        // Raising the ceiling needs privilege; EPERM is tolerated below.
        next.rlim_max = next.rlim_max.max(want);
        next.rlim_cur = want;
        if libc::setrlimit(libc::RLIMIT_NOFILE, &next as *const _) != 0 {
            next = lim;
            next.rlim_cur = next.rlim_max;
            let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &next as *const _);
        }
        let mut after: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut after as *mut _) == 0 {
            eprintln!("nkgrep: NOFILE cur={} max={}", after.rlim_cur, after.rlim_max);
        }
    }
}

/// pread loop into `buf` from offset 0 to EOF (offset-free: safe on a fd
/// shared across rayon workers). Appends like `read_to_end`.
fn pread_all(fd: std::os::unix::io::RawFd, buf: &mut Vec<u8>) -> std::io::Result<()> {
    let mut off: libc::off_t = 0;
    loop {
        if buf.len() == buf.capacity() {
            buf.reserve(8 * 1024);
        }
        // SAFETY: pread into the spare capacity; `set_len` covers exactly
        // the bytes the kernel initialized; EINTR retries, EOF ends.
        let n = unsafe {
            let dst = buf.spare_capacity_mut();
            libc::pread(
                fd,
                dst.as_mut_ptr() as *mut libc::c_void,
                dst.len(),
                off,
            )
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            return Ok(());
        }
        let n = n as usize;
        off += n as libc::off_t;
        // SAFETY: `n` bytes initialized by pread above.
        unsafe {
            buf.set_len(buf.len() + n);
        }
    }
}

fn plain_open_read(path: &str, buf: &mut Vec<u8>) -> std::io::Result<()> {
    use std::io::Read;
    std::fs::File::open(path)?.read_to_end(buf)?;
    Ok(())
}

/// Serve-side file read: warm-fd hit serves stat + pread (no open/close and
/// no path walk); miss or edit opens fresh, validates the fd's own metadata,
/// and caches it. `retried` bounds the EBADF re-read after a concurrent
/// replace closed the fd under us.
fn read_verify_bytes(
    fdc: Option<(&FdCache, u32)>,
    path: &str,
    buf: &mut Vec<u8>,
    retried: bool,
) -> std::io::Result<()> {
    let (cache, id) = match fdc {
        None => return plain_open_read(path, buf),
        Some(x) => x,
    };
    let live = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return plain_open_read(path, buf),
    };
    let (len, modified) = match live.modified() {
        Ok(t) => (live.len(), t),
        Err(_) => return plain_open_read(path, buf),
    };
    let slot = match cache.slots.get(id as usize) {
        Some(s) => s,
        None => return plain_open_read(path, buf),
    };
    // Fast path: per-slot lock only, no open/hash while holding it.
    // Poison-tolerant: a panicked holder must not wedge the daemon.
    if let Some(fd) = slot
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .filter(|e| e.len == len && e.modified == modified)
        .map(|e| e.fd)
    {
        match pread_all(fd, buf) {
            Ok(()) => return Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::EBADF) && !retried => {
                // Lost the fd to a concurrent replace: drop the dead entry
                // and re-read once through the fresh path.
                *slot.lock().unwrap_or_else(|e| e.into_inner()) = None;
                return read_verify_bytes(fdc, path, buf, true);
            }
            Err(e) => return Err(e),
        }
    }
    // Miss or edit: open + stat OUTSIDE the lock so one cold file never
    // stalls other workers' warm pread hits.
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return plain_open_read(path, buf),
    };
    let (flen, fmod) = match f.metadata().and_then(|m| m.modified().map(|t| (m.len(), t))) {
        Ok(x) => x,
        Err(_) => return plain_open_read(path, buf),
    };
    // `f` drops here but the fd must survive: forget the File.
    // SAFETY: `into_raw_fd` transfers ownership to the entry.
    let fresh = {
        use std::os::unix::io::IntoRawFd;
        f.into_raw_fd()
    };
    let fd = {
        let mut guard = slot.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            // Recheck: another worker filled the same generation first.
            Some(e) if e.len == flen && e.modified == fmod => {
                let fd = e.fd;
                // SAFETY: `fresh` came from `into_raw_fd` above and is now
                // surplus; closing exactly once here keeps one owner.
                unsafe {
                    libc::close(fresh);
                }
                fd
            }
            _ => {
                // Replace drops the old entry (closes its fd) if present.
                *guard = Some(CachedFd { fd: fresh, len: flen, modified: fmod });
                fresh
            }
        }
    };
    match pread_all(fd, buf) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EBADF) && !retried => {
            *slot.lock().unwrap_or_else(|e| e.into_inner()) = None;
            read_verify_bytes(fdc, path, buf, true)
        }
        Err(e) => Err(e),
    }
}

#[derive(Serialize, Deserialize)]
struct Query {
    pattern: String,
    top: Option<usize>,
}

/// Ranked candidate file ids with scores. None = no usable literal.
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
fn raw_order(scores: &[f64]) -> Vec<u32> {
    let mut ord: Vec<u32> = (0..scores.len() as u32).collect();
    ord.sort_by(|a, b| {
        scores[*b as usize]
            .partial_cmp(&scores[*a as usize])
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    ord
}

/// Batched parallel verify in descending file-score order with provable
/// top-k early exit (spec §6): every match scores at most its file score
/// (match score = file score − line/1e6), so once k hits are banked, no
/// unverified file whose file score does not exceed the kth-best match
/// score can displace the top-k. Each batch uses the serve pattern
/// (rayon par_iter + flat_map verify); the kth check runs between
/// batches against the batch max (order[0] of the chunk, order is desc).
/// Exiting before a batch whose max does not exceed kth exits before
/// every file a per-file loop would skip — same proof, batch granularity.
/// Final global sort + truncate stays with the caller.
/// ST-5 columnar: banks verbatim match bytes per file (one amortized arena
/// alloc per matched file, zero per hit) with zero Arc traffic; callers
/// flatten metas to a side scores vec for the index-only sort.
fn flat_scores(files: &[FileHits]) -> (Vec<f64>, Vec<(u32, u32)>) {
    let n: usize = files.iter().map(|f| f.metas.len()).sum();
    let mut scores = Vec::with_capacity(n);
    let mut loc = Vec::with_capacity(n);
    for (fi, f) in files.iter().enumerate() {
        for (mi, m) in f.metas.iter().enumerate() {
            scores.push(m.score);
            loc.push((fi as u32, mi as u32));
        }
    }
    (scores, loc)
}

/// Decode banked match bytes with the exact eager expression
/// (`from_utf8_lossy` then char-trim of `\n`/`\r`): valid UTF-8 borrows the
/// arena, only invalid-UTF8 hits allocate — the same hits as before.
fn banked_text<'a>(fh: &'a FileHits, m: &HitMeta) -> std::borrow::Cow<'a, str> {
    let raw = &fh.arena[m.start as usize..m.end as usize];
    let cow = String::from_utf8_lossy(raw);
    match cow {
        std::borrow::Cow::Borrowed(b) => std::borrow::Cow::Borrowed(b.trim_end_matches(|c| c == '\n' || c == '\r')),
        std::borrow::Cow::Owned(o) => {
            std::borrow::Cow::Owned(o.trim_end_matches(|c| c == '\n' || c == '\r').to_string())
        }
    }
}

fn parallel_verify_batched_raw(
    idx: &Index,
    matcher: &RegexMatcher,
    order: &[u32],
    scores: &[f64],
    top: Option<usize>,
) -> Vec<FileHits> {
    if top == Some(0) {
        return vec![];
    }
    const BATCH: usize = 64;
    // Full queries never early-exit (k = MAX), so the sequential batch
    // waves are pure barrier overhead: verify all candidates in one wave.
    // Top-k keeps the batched proof path below untouched (§6).
    if top.is_none() {
        return order
            .par_iter()
            .filter_map(|id| {
                verify_one_raw(*id, &idx.files[*id as usize], matcher, scores[*id as usize])
            })
            .collect();
    }
    let k = top.unwrap_or(usize::MAX);
    let mut all: Vec<FileHits> = vec![];
    let mut total = 0usize;
    let mut kth = f64::NEG_INFINITY;
    let mut done = 0usize;
    for chunk in order.chunks(BATCH) {
        if total >= k && scores[chunk[0] as usize] <= kth {
            eprintln!("nkgrep: early exit after {done} of {} files", order.len());
            break;
        }
        // Per-file exit at file granularity (spec §6, same proof as the
        // batch check: every match scores at most its file score, so a file
        // whose file score does not exceed kth contributes no top-k hit).
        // Same `<= kth` threshold as the batch exit, applied per file, so
        // the surviving set — ties included — matches the batch-only path.
        let armed = total >= k;
        let kth_now = kth;
        let mut batch: Vec<FileHits> = chunk
            .par_iter()
            .filter(|id| !armed || scores[**id as usize] > kth_now)
            .filter_map(|id| {
                verify_one_raw(*id, &idx.files[*id as usize], matcher, scores[*id as usize])
            })
            .collect();
        total += batch.iter().map(|f| f.metas.len()).sum::<usize>();
        all.append(&mut batch);
        done += chunk.len();
        if total >= k {
            let (mut s, _) = flat_scores(&all);
            s.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
            kth = s[k - 1];
        }
    }
    all
}


fn handle_client(stream: TcpStream, idx: Arc<Index>, fdc: Arc<FdCache>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut writer = std::io::BufWriter::with_capacity(64 * 1024, stream);
    let mut line = String::new();
    while reader.read_line(&mut line).unwrap_or(0) > 0 {
        let t0 = Instant::now();
        // Columnar serve emission: borrow-banked FileHits through the fd
        // cache, rank once over the side scores vec, escape each unique
        // path once, emit via emit_raw_with_path, single socket write.
        // Byte-identical wire (one object per line plus the done line);
        // no per-hit serde struct setup, no Arc path clones, no per-hit
        // path escaping.
        let mut broken = false;
        match serde_json::from_str::<Query>(line.trim()) {
            Err(_) => {}
            Ok(q) => match build_matcher(&q.pattern) {
                Err(e) => {
                    if writeln!(writer, "{{\"error\":\"{e}\"}}").is_err() {
                        broken = true;
                    }
                }
                Ok(matcher) => {
                    let order = ranked_candidates(&idx, &q.pattern).unwrap_or_else(|| {
                        (0..idx.files.len() as u32).map(|id| (id, 0.0)).collect()
                    });
                    let files: Vec<FileHits> = order
                        .par_iter()
                        .filter_map(|(id, s)| {
                            verify_one_raw_cached(
                                *id,
                                &idx.files[*id as usize],
                                &matcher,
                                *s,
                                Some((&*fdc, *id)),
                            )
                        })
                        .collect();
                    let (hit_scores, loc) = flat_scores(&files);
                    let mut ord = raw_order(&hit_scores);
                    if let Some(n) = q.top {
                        ord.truncate(n);
                    }
                    let mut esc: Vec<Option<Vec<u8>>> = vec![None; idx.files.len()];
                    for &i in &ord {
                        let (fi, _) = loc[i as usize];
                        let pid = files[fi as usize].pid as usize;
                        if esc[pid].is_none() {
                            let ps = &idx.files[pid];
                            let mut v = Vec::with_capacity(ps.len() + 2);
                            push_escaped_json(&mut v, ps);
                            esc[pid] = Some(v);
                        }
                    }
                    let mut buf = Vec::with_capacity(ord.len() * 160);
                    for &i in &ord {
                        let (fi, mi) = loc[i as usize];
                        let fh = &files[fi as usize];
                        let m = &fh.metas[mi as usize];
                        let text = banked_text(fh, m);
                        emit_raw_with_path(
                            &mut buf,
                            esc[fh.pid as usize].as_ref().unwrap(),
                            m.line,
                            &text,
                            m.score,
                        );
                    }
                    if writer.write_all(&buf).is_err() {
                        broken = true;
                    }
                }
            },
        }
        if writeln!(writer, "{{\"done\":true,\"ms\":{}}}", t0.elapsed().as_millis()).is_err() {
            broken = true;
        }
        if writer.flush().is_err() {
            broken = true;
        }
        if broken {
            break;
        }
        line.clear();
    }
}

fn serve_info_path(idx_path: &str) -> String {
    format!("{idx_path}.serve.json")
}

#[derive(Serialize, Deserialize)]
struct ServerInfo {
    pid: u32,
    port: u16,
}

fn save_serve_info(idx_path: &str, port: u16) {
    let info = ServerInfo { pid: std::process::id(), port };
    if let Ok(s) = serde_json::to_string(&info) {
        let _ = std::fs::write(serve_info_path(idx_path), s + "\n");
    }
}

/// Port recorded by a running `serve` for this index, or None when no
/// server registered (missing or corrupt file reads as absent).
fn load_serve_port(idx_path: &str) -> Option<u16> {
    let data = std::fs::read_to_string(serve_info_path(idx_path)).ok()?;
    serde_json::from_str::<ServerInfo>(data.trim()).ok().map(|i| i.port)
}

fn cmd_serve(idx_path: &str, port: u16) {
    let idx = Arc::new(load_index_for_serve(idx_path));
    // O3: daemon-global warm-fd cache + fd headroom for one fd per file.
    bump_nofile_for_cache(idx.files.len());
    let fdc = Arc::new(FdCache::new(idx.files.len()));
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    let bound = listener.local_addr().map(|a| a.port()).unwrap_or(port);
    save_serve_info(idx_path, bound);
    eprintln!("nkgrep: serving {} files on 127.0.0.1:{bound}", idx.files.len());
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let idx = idx.clone();
                let fdc = fdc.clone();
                std::thread::spawn(move || handle_client(s, idx, fdc));
            }
            Err(e) => eprintln!("nkgrep: accept error: {e}"),
        }
    }
}

/// Hot client fetch: returns the server's hit lines verbatim plus the hit
/// count, without parsing Hits or re-serializing them. The server already
/// emits final ranked order, so the bytes are stdout-ready; the old
/// parse-then-to_string round trip only burned ~8-14 ms on heavy full.
/// Skips blank lines and error lines exactly as the old `from_str::<Hit>`
/// fallible parse dropped them (a bad-regex error reply yields empty
/// stdout, exit 1 below).
fn client_query(port: u16, pattern: &str, top: Option<usize>) -> (Vec<u8>, usize) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let req = serde_json::to_string(&Query {
        pattern: pattern.to_string(),
        top,
    })
    .unwrap();
    stream.write_all(req.as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
    let mut reader = BufReader::new(stream);
    let mut raw = vec![];
    let mut matches = 0usize;
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let t = line.trim();
        if t.contains("\"done\"") {
            break;
        }
        if t.is_empty() || t.contains("\"error\"") {
            continue;
        }
        matches += 1;
        raw.extend_from_slice(line.as_bytes());
    }
    (raw, matches)
}
/// Serve-first probe for `--use-index`: connect to the daemon registered in
/// `<index>.serve.json`, if any. Any failure (no file, no listener, bad
/// reply) returns None so the caller falls back to the cold index load.
fn try_serve_query(idx_path: &str, pattern: &str, top: Option<usize>) -> Option<(Vec<u8>, usize)> {
    let port = load_serve_port(idx_path)?;
    let mut stream = TcpStream::connect_timeout(
        &"127.0.0.1".parse().ok().map(|ip| std::net::SocketAddr::new(ip, port))?,
        Duration::from_millis(200),
    )
    .ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok()?;
    let req = serde_json::to_string(&Query { pattern: pattern.to_string(), top }).ok()?;
    stream.write_all(req.as_bytes()).ok()?;
    stream.write_all(b"\n").ok()?;
    let mut reader = BufReader::new(stream);
    // Raw passthrough: server bytes are already final-ordered hit JSON, one
    // per line. Collect them verbatim instead of parsing each Hit and
    // re-serializing it. Blank lines are skipped and error lines fail over
    // to the cold path, matching the old fallible-parse behavior.
    let mut raw = vec![];
    let mut matches = 0usize;
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return None;
        }
        let t = line.trim();
        if t.contains("\"done\"") {
            break;
        }
        if t.contains("\"error\"") {
            return None;
        }
        if t.is_empty() {
            continue;
        }
        matches += 1;
        raw.extend_from_slice(line.as_bytes());
    }
    Some((raw, matches))
}
/// Cold-emission JSON string escaper (Escaper region): byte-identical to
/// serde_json for `&str` input. Only `"`, `\` and bytes < 0x20 escape;
/// `\n`/`\r`/`\t`/0x08/0x0C use short forms, other controls `\u00XX`
/// (lowercase hex, matching serde_json); UTF-8 multibyte passes through.
/// memchr2 skips the common quote/backslash-free run; the gap holds only
/// rare controls, scanned inline. Floats are NOT touched here: `emit_hit_json`
/// formats `score` via serde_json so ryu output stays equality-exact.
fn push_escaped_json(out: &mut Vec<u8>, s: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let b = s.as_bytes();
    let mut start = 0usize;
    let mut i = 0usize;
    // First index in `b[pos..end)` holding a byte < 0x20, or `end` when the
    // gap is control-free. SWAR fast path (ST-8 text-half): each 8-byte word
    // is tested exactly via the zero-byte trick on `w & 0xE0..` (a byte is
    // < 0x20 iff its top three bits are clear), so the common control-free
    // gap skips the per-byte branch loop below; a flagged word falls through
    // to the exact per-byte scan, which must find the control (the word test
    // is exact, never a false positive). Tail bytes scan inline.
    #[inline]
    fn first_control(b: &[u8], pos: usize, end: usize) -> usize {
        const E0: u64 = 0xE0E0_E0E0_E0E0_E0E0;
        const LO: u64 = 0x0101_0101_0101_0101;
        const HI: u64 = 0x8080_8080_8080_8080;
        let mut k = pos;
        let stop = pos + (end - pos) / 8 * 8;
        while k < stop {
            let v = u64::from_le_bytes(b[k..k + 8].try_into().unwrap());
            let m = v & E0;
            if (m.wrapping_sub(LO) & !m & HI) != 0 {
                break;
            }
            k += 8;
        }
        while k < end {
            if b[k] < 0x20 {
                return k;
            }
            k += 1;
        }
        end
    }
    loop {
        let rel = memchr::memchr2(b'"', b'\\', &b[i..]);
        let end = match rel {
            Some(r) => i + r,
            None => b.len(),
        };
        // Control-free gaps (the corpus-common case: 0 of 51410 heavy texts
        // hold a byte < 0x20) skip the per-byte loop; the escape loop below
        // then resumes from the first real control with `start` untouched,
        // which emits byte-identical output.
        let mut j = first_control(b, i, end);
        while j < end {
            let c = b[j];
            if c < 0x20 {
                out.extend_from_slice(&b[start..j]);
                match c {
                    b'\n' => out.extend_from_slice(b"\\n"),
                    b'\r' => out.extend_from_slice(b"\\r"),
                    b'\t' => out.extend_from_slice(b"\\t"),
                    0x08 => out.extend_from_slice(b"\\b"),
                    0x0C => out.extend_from_slice(b"\\f"),
                    _ => {
                        out.extend_from_slice(b"\\u00");
                        out.push(HEX[(c >> 4) as usize]);
                        out.push(HEX[(c & 0xF) as usize]);
                    }
                }
                start = j + 1;
            }
            j += 1;
        }
        match rel {
            Some(_) => {
                out.extend_from_slice(&b[start..end]);
                out.extend_from_slice(if b[end] == b'"' { b"\\\"" } else { b"\\\\" });
                start = end + 1;
                i = end + 1;
            }
            None => break,
        }
    }
    out.extend_from_slice(&b[start..]);
}

/// Manual cold-emission line from columnar fields (ST-5): byte-identical to
/// `emit_hit_with_path` (same field order/separators, same path escaper,
/// same serde/ryu score path); only the source of the fields differs.
fn emit_raw_with_path(buf: &mut Vec<u8>, path_esc: &[u8], line: u64, text: &str, score: f64) {
    buf.extend_from_slice(b"{\"path\":\"");
    buf.extend_from_slice(path_esc);
    buf.extend_from_slice(b"\",\"line\":");
    // itoa (ST-8 text-half): manual digits, byte-identical to Display, no
    // core::fmt machinery per hit (~16 ns/hit on heavy-full replay).
    let mut tmp = [0u8; 20];
    let mut v = line;
    let mut len = 0usize;
    if v == 0 {
        tmp[19] = b'0';
        len = 1;
    } else {
        while v > 0 {
            len += 1;
            tmp[20 - len] = b'0' + (v % 10) as u8;
            v /= 10;
        }
    }
    buf.extend_from_slice(&tmp[20 - len..]);
    buf.extend_from_slice(b",\"text\":\"");
    push_escaped_json(buf, text);
    buf.extend_from_slice(b"\",\"score\":");
    serde_json::to_writer(&mut *buf, &score).unwrap();
    buf.extend_from_slice(b"}\n");
}

/// Manual cold-emission Hit line with a pre-escaped path: field order and
/// separators match the derived Serialize impl; only text/path escaping is
/// hand-rolled, floats stay on the serde (ryu) path. Test-only since the
/// cold path went columnar; the differential equality pins it byte-identical.
#[cfg(test)]
fn emit_hit_with_path(buf: &mut Vec<u8>, h: &Hit, path_esc: &[u8]) {
    emit_raw_with_path(buf, path_esc, h.line, &h.text, h.score)
}

/// Manual cold-emission Hit line: escapes the path inline (tests, fallback).
#[cfg(test)]
fn emit_hit_json(buf: &mut Vec<u8>, h: &Hit) {
    let mut p = Vec::with_capacity(h.path.len() + 2);
    push_escaped_json(&mut p, &h.path);
    emit_hit_with_path(buf, h, &p);
}

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
    // escaped paths. Serve emits the same banked path; the equality pins both
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
    // rayon ramp. serde_json remains the differential equality in tests.
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
mod literal_tests {
    use super::*;

    fn sorted_branches(pat: &str) -> Option<Vec<Vec<u32>>> {
        query_grams(pat).map(|mut ors| {
            for b in &mut ors {
                b.sort();
            }
            ors.sort();
            ors
        })
    }

    #[test]
    fn escaped_pipe_stays_one_branch() {
        // `abc\|def` is a single literal `abc|def`, not an alternation.
        let got = sorted_branches("abc\\|def").unwrap();
        assert_eq!(got.len(), 1, "escaped pipe must not split: {got:?}");
        assert!(got[0].contains(&gram_pack(b"abc")), "{got:?}");
        assert!(got[0].contains(&gram_pack(b"def")), "{got:?}");
    }

    #[test]
    fn escaped_pipe_branch_still_indexes() {
        // Naive `split('|')` yields a bare `x` branch -> None (full scan).
        // Proper parse keeps 2 branches, both with usable literals.
        let got = sorted_branches("needle_1\\|x|NEEDLE_ALPHA").unwrap();
        assert_eq!(got.len(), 2, "{got:?}");
    }

    #[test]
    fn class_pipe_does_not_split() {
        let got = sorted_branches("[a|b]+needle_1").unwrap();
        assert_eq!(got.len(), 1, "class pipe must not split: {got:?}");
        assert!(got[0].contains(&gram_pack(b"nee")), "{got:?}");
    }

    #[test]
    fn group_alternation_splits() {
        let got = sorted_branches("(needle_1|needle_2)_suffix").unwrap();
        assert_eq!(got.len(), 2, "{got:?}");
    }
    #[test]
    fn cached_verify_matches_plain() {
        // The fd-cache read path (`Some`) must bank the same hits as the
        // plain path (`None`): byte-identical decoded text, line, and score.
        let dir = std::env::temp_dir().join(format!("nkgrep_cached_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.txt");
        std::fs::write(&a, "needle here\nsecond needle\n").unwrap();
        let ap = a.to_string_lossy().into_owned();
        let matcher = RegexMatcher::new("needle").unwrap();
        let fdc = FdCache::new(1);
        let plain = verify_one_raw(0, &ap, &matcher, 10.0).expect("plain must hit");
        let cached = verify_one_raw_cached(0, &ap, &matcher, 10.0, Some((&fdc, 0)))
            .expect("cached must hit");
        assert_eq!(cached.metas.len(), plain.metas.len());
        for (c, p) in cached.metas.iter().zip(plain.metas.iter()) {
            assert_eq!((c.line, c.score), (p.line, p.score));
            assert_eq!(banked_text(&cached, c), banked_text(&plain, p));
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn no_literal_falls_back() {
        assert!(query_grams("a|b").is_none());
        assert!(query_grams(".*").is_none());
        assert!(query_grams("a\\|b").is_none()); // single branch, runs < 3
    }

    #[test]
    fn plain_queries_unchanged() {
        assert!(query_grams("TODO_FIXME_ALPHA").is_some());
        assert_eq!(
            sorted_branches("needle_1|needle_2|needle_3").unwrap().len(),
            3
        );
        assert_eq!(sorted_branches("fn parse_config").unwrap().len(), 1);
    }
    #[test]
    fn pack_bijective_and_ordered() {
        // Bijective: distinct triples pack distinctly, top byte stays zero.
        let mut seen = std::collections::HashSet::new();
        for a in [0u8, 1, 65, 95, 122, 200, 255] {
            for b in [0u8, 1, 65, 95, 122, 200, 255] {
                for c in [0u8, 1, 65, 95, 122, 200, 255] {
                    let k = gram_pack(&[a, b, c]);
                    assert_eq!(k >> 24, 0, "top byte must stay zero");
                    assert_eq!(((k >> 16) & 0xFF) as u8, a);
                    assert_eq!(((k >> 8) & 0xFF) as u8, b);
                    assert_eq!((k & 0xFF) as u8, c);
                    assert!(seen.insert(k), "collision on [{a}, {b}, {c}]");
                }
            }
        }
        // Numeric order equals lexicographic byte order.
        let mut trips: Vec<[u8; 3]> = vec![
            *b"abc", *b"abd", *b"bac", *b"aaa", *b"zzz", *b"a_c", *b"_aa",
        ];
        trips.sort();
        let mut packed: Vec<u32> = trips.iter().map(|t| gram_pack(t)).collect();
        packed.sort();
        assert_eq!(
            packed,
            trips.iter().map(|t| gram_pack(t)).collect::<Vec<_>>()
        );
    }
    #[test]
    fn top_zero_indexed_matches_scan_empty() {
        let dir = std::env::temp_dir().join(format!("nkgrep_top0_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.txt");
        let b = dir.join("b.txt");
        std::fs::write(&a, "needle_haystack_content\n").unwrap();
        std::fs::write(&b, "needle_haystack_content\n").unwrap();
        let idx = Index {
            root: String::new(),
            root_dev: 0,
            root_ino: 0,
            files: vec![
                a.to_string_lossy().into_owned(),
                b.to_string_lossy().into_owned(),
            ],
            postings: HashMap::new(),
        };
        let matcher = RegexMatcher::new("needle_haystack_content").unwrap();
        let order = vec![0u32, 1u32];
        let scores = vec![10.0f64, 5.0f64];
        let batched = parallel_verify_batched_raw(&idx, &matcher, &order, &scores, Some(0));
        // Columnar flat scan (serve semantics): full verify, rank over side
        // scores, top-0 truncate.
        let scanned_all: Vec<FileHits> = [(0u32, 10.0f64), (1u32, 5.0f64)]
            .into_iter()
            .filter_map(|(id, s)| verify_one_raw_cached(id, &idx.files[id as usize], &matcher, s, None))
            .collect();
        let (scanned_scores, _) = flat_scores(&scanned_all);
        let mut scanned_ord = raw_order(&scanned_scores);
        scanned_ord.truncate(0);
        assert!(batched.is_empty(), "top=0 batched must return 0 hits");
        assert!(scanned_ord.is_empty(), "top=0 scan must return 0 hits");
        assert!(!scanned_all.is_empty(), "fixture must match without top");
        std::fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
mod escape_tests {
    use super::*;

    fn quoted_manual(s: &str) -> Vec<u8> {
        let mut m = Vec::with_capacity(s.len() + 2);
        m.push(b'"');
        push_escaped_json(&mut m, s);
        m.push(b'"');
        m
    }

    fn check_str(s: &str) {
        let o = serde_json::to_vec(&s).unwrap();
        assert_eq!(quoted_manual(s), o, "escape divergence on {s:?}");
    }

    fn check_hit(path: &str, line: u64, text: &str, score: f64) {
        let h = Hit {
            path: Arc::new(path.to_string()),
            line,
            text: text.to_string(),
            score,
        };
        let mut m = Vec::new();
        emit_hit_json(&mut m, &h);
        let mut o = serde_json::to_vec(&h).unwrap();
        o.push(b'\n');
        assert_eq!(m, o, "hit divergence on {path:?}:{line}:{text:?}:{score:?}");
    }

    #[test]
    fn fuzz_vs_serde_full_matrix() {
        // Every single byte 0x00-0x7F standalone.
        for b in 0u8..=0x7Fu8 {
            check_str(&char::from_u32(b as u32).unwrap().to_string());
        }
        // Every control/quote/backslash embedded in text.
        let mut specials: Vec<char> = (0u8..0x20).map(|b| b as char).collect();
        specials.push('"');
        specials.push('\\');
        for c in &specials {
            check_str(&format!("a{c}b"));
            check_str(&format!("{c}lead"));
            check_str(&format!("trail{c}"));
        }
        // Full pair matrix over specials (byte-identical gate).
        for a in &specials {
            for b in &specials {
                check_str(&format!("{a}{b}"));
                check_str(&format!("x{a}y{b}z"));
            }
        }
        // Must-NOT-escape: DEL, high bytes via multibyte, slashes.
        for s in [
            "\x7f",
            "caf\u{e9}",
            "\u{1f600}",
            "\u{fffd}",
            "\u{4e2d}\u{6587}",
            "e\u{301}",
            "a/b\\c",
            "/abs/path/x.txt",
            "tab\there",
            "nl\nhere",
            "cr\rhere",
            "bs\x08here",
            "ff\x0chere",
            "q\"q",
            "b\\b",
            "\"quoted\"",
            "\\\\unc\\\\path",
            "",
            "plain ascii line with spaces 123",
        ] {
            check_str(s);
        }
        // Hit-level sweep: lines x scores x tricky strings. Floats stay on
        // the serde path (ryu); this locks byte-identity including score.
        let texts = [
            "plain",
            "q\"q\\",
            "a\nb\tc",
            "\x01\x02\x1f mid \x7f",
            "uni \u{1f600} \u{fffd}",
            "",
            "trail\\",
        ];
        let lines = [0u64, 1, 42, u64::MAX];
        let scores = [
            0.0,
            -0.0,
            1.5,
            -42.25,
            123456.789,
            1e-7,
            1e300,
            99.999999,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::NAN,
        ];
        for t in texts {
            for l in lines {
                for s in scores {
                    check_hit("corpus/pkg_0/m_0.txt", l, t, s);
                    check_hit("we\"ird\\path\x01.txt", l, t, s);
                }
            }
        }
    }

    #[test]
    fn fuzz_vs_serde_corpus_bytes() {
        // Every line of the real bench corpus as `text`, every file path as
        // `path`: the differential equality over actual emission bytes.
        let root = std::path::Path::new("bench/corpus");
        if !root.exists() {
            return;
        }
        let mut files: Vec<std::path::PathBuf> = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    files.push(p);
                }
            }
        }
        files.sort();
        let mut n = 0usize;
        for p in &files {
            check_str(&p.to_string_lossy());
            let data = std::fs::read(p).unwrap();
            for line in data.split(|&b| b == b'\n') {
                let s = String::from_utf8_lossy(line);
                check_str(&s);
                // Spot Hit-level check per file: first line only keeps it fast.
                if n < 2000 && line.as_ptr() == data.as_ptr() {
                    check_hit(&p.to_string_lossy(), 1, &s, 12.5);
                }
                n += 1;
                if n >= 60000 {
                    return;
                }
            }
        }
        assert!(n > 1000, "corpus fuzz saw too few lines: {n}");
    }
}
