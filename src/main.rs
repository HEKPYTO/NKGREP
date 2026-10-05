// nkg — ranked trigram code search.

use grep_regex::{RegexMatcher, RegexMatcherBuilder};
use grep_searcher::Searcher;
use grep_searcher::{SearcherBuilder, Sink, SinkMatch};
use ignore::overrides::OverrideBuilder;
use ignore::WalkBuilder;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, IsTerminal, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
mod prefilter;
#[derive(Serialize, Deserialize, Clone)]
#[cfg(test)]
struct Hit {
    path: std::sync::Arc<String>,
    line: u64,
    text: String,
    score: f64,
}

/// Columnar hit: per-file arena banks match bytes verbatim; decode at emit.
/// Wire bytes identical to the eager path.
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
    /// Line-start offsets over `arena`; empty unless context>0 (then arena
    /// holds the full file bytes verbatim).
    line_starts: Vec<u32>,
}

struct ColCollector {
    arena: Vec<u8>,
    metas: Vec<HitMeta>,
    path_bonus: f64,
    /// Per-file cap handed to grep-searcher as `max_matches`: `Some(1)` for
    /// `-l`/`-q` (one path per file) and `Some(n)` for `-m n`. Without it the
    /// file was scanned to the end and the cap applied afterwards, so a `-m 1`
    /// search of a 26 MB file cost the same as printing every match.
    match_limit: Option<u64>,
}

impl Sink for ColCollector {
    type Error = Box<dyn std::error::Error>;

    fn matched(&mut self, _searcher: &Searcher, m: &SinkMatch<'_>) -> Result<bool, Self::Error> {
        let line_no = m.line_number().unwrap_or(1).max(1);
        let bytes = m.bytes();
        let score = self.path_bonus - (line_no as f64) / 1e6;
        let start = self.arena.len() as u32;
        self.arena.extend_from_slice(bytes);
        let end = self.arena.len() as u32;
        self.metas.push(HitMeta {
            line: line_no,
            start,
            end,
            score,
        });
        if self.match_limit.is_some() {
            return Ok(false);
        }
        Ok(true)
    }
}

/// Cold columnar verify arguments, bundled so the entry stays under
/// clippy's argument-count limit (same contract as `CachedVerify`).
struct VerifyInput<'a> {
    err: &'a AtomicBool,
    pid: u32,
    path: &'a str,
    matcher: &'a RegexMatcher,
    file_score: f64,
    before: usize,
    after: usize,
    invert: bool,
    follow: bool,
    /// Per-file match cap for the searcher; see `ColCollector::match_limit`.
    match_limit: Option<u64>,
}

/// Request-scoped loud-verify latch (I/O-error exit-2 contract): verify runs
/// on rayon workers and returns `Option`, so a per-file open/read failure
/// records itself here instead of vanishing into a `None`. Each request owns
/// its latch (`&AtomicBool` threaded through the verify inputs); callers fold
/// `take_verify_io_error(err)` into `walk_error` before every emission, so an
/// unreadable file exits 2 instead of silently matching nothing. A symlink
/// refused under no-follow open (swapped in after the walk) still skips
/// silently — the same outcome as a walk-filtered file.
/// Report one unreadable corpus file from a verify worker into the
/// request-scoped latch; the caller turns it into exit 2. Returns false so
/// call sites keep their shape.
fn note_verify_io_error(err: &AtomicBool, path: &str, e: &std::io::Error, follow: bool) -> bool {
    let raced_link = !follow
        && std::fs::symlink_metadata(std::path::Path::new(path))
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
    if !raced_link {
        eprintln!("nkg: cannot read {path}: {e}");
        err.store(true, Ordering::Relaxed);
    }
    false
}
/// Drain a request-scoped loud-verify latch (false when no worker failed
/// since the last drain); folded into `walk_error` before every emission.
fn take_verify_io_error(err: &AtomicBool) -> bool {
    err.swap(false, Ordering::Relaxed)
}

/// No-context wrapper over `verify_one_raw_ctx` (before=after=0, invert=false).
fn verify_one_raw(
    err: &AtomicBool,
    pid: u32,
    path: &str,
    matcher: &RegexMatcher,
    file_score: f64,
    follow: bool,
    match_limit: Option<u64>,
) -> Option<FileHits> {
    verify_one_raw_ctx(VerifyInput {
        err,
        pid,
        path,
        matcher,
        file_score,
        before: 0,
        after: 0,
        invert: false,
        follow,
        match_limit,
    })
}

/// Columnar verify: TLS Searcher + 64KB buf + verbatim-banked sink; hit set,
/// scores, and rank order identical with or without context/invert.
fn verify_one_raw_ctx(args: VerifyInput<'_>) -> Option<FileHits> {
    let VerifyInput {
        err,
        pid,
        path,
        matcher,
        file_score,
        before,
        after,
        invert,
        follow,
        match_limit,
    } = args;
    use std::cell::RefCell;
    thread_local! {
        static SEARCHER: RefCell<Searcher> = RefCell::new(SearcherBuilder::new().build());
        static BUF: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(64 * 1024));
    }
    let mut sink = ColCollector {
        arena: vec![],
        metas: vec![],
        path_bonus: file_score,
        match_limit,
    };
    // `with` (not try_with): destroyed-TLS fallback returning empty would
    // silently drop matches and break set equality; loud panic is correct.
    // Any IO/search error still discards partial hits, as before.
    let ok = SEARCHER.with(|s| {
        BUF.with(|b| {
            let mut buf = b.borrow_mut();
            buf.clear();
            // Inverted search needs `invert_match(true)`; the TLS searcher is
            // fixed-config, so invert builds a local searcher per file (no
            // TLS pair to keep in sync; invert is off the hot default path).
            // The `match` reads the initial None on the default path, so no
            // dead assignment (warnings are denied).
            // `-l`/`-q` want the path, not the rows, so cap the searcher at one
            // match per file. `max_matches` is grep-searcher's own mechanism
            // for exactly this and is checked per match, so the file stops
            // being scanned the moment it hits. The TLS searcher is
            // fixed-config, so the capped one is built per file instead.
            let mut local: Option<Searcher> = None;
            let mut normal = s.borrow_mut();
            if let Some(limit) = match_limit {
                local = Some(SearcherBuilder::new().max_matches(Some(limit)).build());
            } else if invert {
                local = Some(SearcherBuilder::new().invert_match(true).build());
            }
            let searcher: &mut Searcher = match local.as_mut() {
                Some(inv) => inv,
                None => &mut normal,
            };
            (|| -> std::io::Result<bool> {
                use std::io::{Read, Seek, SeekFrom};
                // No-follow open (unless -L): a symlink swapped in after
                // the walk is refused here, never followed outside.
                let mut f = open_verify_file(std::path::Path::new(path), follow)?;
                // Binary skip on the head only, so a file never has to be
                // resident to be classified: `is_binary` reads at most 8 KiB,
                // and the index never admits binaries, so verify must skip
                // them identically or indexed stops equalling scan.
                let mut head = [0u8; 8192];
                let n = f.read(&mut head)?;
                // Per-file early exit: an empty file holds no lines and no
                // matches; skip searcher setup. Result identical to searching.
                if n == 0 {
                    return Ok(true);
                }
                if memchr::memchr(0, &head[..n]).is_some() {
                    return Ok(true);
                }
                if before == 0 && after == 0 {
                    // No context to attach, so nothing needs the bytes after
                    // the match: stream the file instead of holding it whole.
                    // `search_reader` is the same engine and matcher as
                    // `search_slice`, so the banked hit set is identical and
                    // peak memory stops scaling with the largest file in the
                    // tree -- the difference between 6 MB and 390 MB of RSS on
                    // a corpus of a few large files.
                    f.seek(SeekFrom::Start(0))?;
                    return Ok(searcher.search_reader(matcher, &mut f, &mut sink).is_ok());
                }
                // Context lines are decoded by byte range against the whole
                // file, so this path stays buffered.
                f.seek(SeekFrom::Start(0))?;
                f.read_to_end(&mut buf)?;
                Ok(searcher.search_slice(matcher, &buf, &mut sink).is_ok())
            })()
            .unwrap_or_else(|e| note_verify_io_error(err, path, &e, follow))
        })
    });
    if ok && !sink.metas.is_empty() {
        let mut fh = FileHits {
            pid,
            arena: sink.arena,
            metas: sink.metas,
            line_starts: vec![],
        };
        if before > 0 || after > 0 {
            // The TLS buffer still holds this file's bytes (cleared only on
            // the next call); attach copies them into the arena — no extra
            // read, one copy, no duplicate storage.
            BUF.with(|b| attach_context(&mut fh, &b.borrow()));
        }
        Some(fh)
    } else {
        None
    }
}
fn verify_one_raw_cached(
    err: &AtomicBool,
    pid: u32,
    path: &str,
    matcher: &RegexMatcher,
    file_score: f64,
    fdc: Option<(&FdCache, u32)>,
    follow: bool,
) -> Option<FileHits> {
    verify_one_raw_cached_ctx(CachedVerify {
        err,
        pid,
        path,
        matcher,
        file_score,
        before: 0,
        after: 0,
        fdc,
        invert: false,
        follow,
    })
}

struct CachedVerify<'a> {
    err: &'a AtomicBool,
    pid: u32,
    path: &'a str,
    matcher: &'a RegexMatcher,
    file_score: f64,
    before: usize,
    after: usize,
    fdc: Option<(&'a FdCache, u32)>,
    invert: bool,
    follow: bool,
}

/// Serve-side columnar verify with context attach: same TLS Searcher +
/// 64 KB buffer + search_slice core and verbatim-banked sink as
/// `verify_one_raw_ctx`, but the file bytes come through the daemon fd
/// cache (`read_verify_bytes`). Context attach is the same post-pass over
/// the surviving hits; the hit set is identical either way.
fn verify_one_raw_cached_ctx(args: CachedVerify<'_>) -> Option<FileHits> {
    let CachedVerify {
        err,
        pid,
        path,
        matcher,
        file_score,
        before,
        after,
        fdc,
        invert,
        follow,
    } = args;
    use std::cell::RefCell;
    thread_local! {
        static SEARCHER: RefCell<Searcher> = RefCell::new(SearcherBuilder::new().build());
        static BUF: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(64 * 1024));
    }
    let mut sink = ColCollector {
        arena: vec![],
        metas: vec![],
        path_bonus: file_score,
        match_limit: None,
    };
    // `with` (not try_with): destroyed-TLS fallback returning empty would
    // silently drop matches and break set equality; loud panic is correct.
    // Any IO/search error still discards partial hits, as before.
    let ok = SEARCHER.with(|s| {
        BUF.with(|b| {
            let mut buf = b.borrow_mut();
            buf.clear();
            // Same local-inverted-searcher contract as the cold twin.
            let mut local: Option<Searcher> = None;
            let mut normal = s.borrow_mut();
            if invert {
                local = Some(SearcherBuilder::new().invert_match(true).build());
            }
            let searcher: &mut Searcher = match local.as_mut() {
                Some(inv) => inv,
                None => &mut normal,
            };
            (|| -> std::io::Result<bool> {
                read_verify_bytes(fdc, path, &mut buf, false, follow)?;
                // Twin of the `verify_one_raw` early exit: empty files hold
                // no matches; skip searcher setup identically.
                if buf.is_empty() {
                    return Ok(true);
                }
                // Symmetric with `cmd_index`: binary files are never indexed,
                // so verify skips them identically (indexed==scan).
                if is_binary(&buf) {
                    return Ok(true);
                }
                Ok(searcher.search_slice(matcher, &buf, &mut sink).is_ok())
            })()
            .unwrap_or_else(|e| note_verify_io_error(err, path, &e, follow))
        })
    });
    if ok && !sink.metas.is_empty() {
        let mut fh = FileHits {
            pid,
            arena: sink.arena,
            metas: sink.metas,
            line_starts: vec![],
        };
        if before > 0 || after > 0 {
            // Same TLS-buffer reuse as the cold twin: the buffer still holds
            // this file's bytes; attach copies them into the arena.
            BUF.with(|b| attach_context(&mut fh, &b.borrow()));
        }
        Some(fh)
    } else {
        None
    }
}

/// Postings as one key-sorted run: `keys[i]` owns
/// `ids[off[i]..off[i+1]]`. Real code has a long-tail trigram distribution —
/// 67k postings over 2k files, against 459 over 3k for a dense synthetic
/// corpus — so the map form paid one allocation plus a hash insert per
/// posting, on the critical path of every cold query. Three arrays and a
/// binary search replace that.
///
/// The JSON form on disk is unchanged (`{key: [ids]}`), so no index needs
/// rebuilding and no stored file is invalidated by this representation.
/// Postings as one key-sorted run: `keys[i]` owns the ids of run `i`. Real
/// code has a long-tail trigram distribution — 67k postings over 2k files,
/// against 459 over 3k for a dense synthetic corpus — so the original map paid
/// one allocation plus a hash insert per posting on the critical path of every
/// cold query.
///
/// `Raw` goes further and leaves the ids in their on-disk little-endian bytes:
/// building only the key/offset table measured 0.26 ms against 1.96 ms to push
/// all 2.1M ids into a `Vec`, and a query touches a handful of runs out of
/// 67k. `Owned` remains for the JSON path, which must tokenize the document
/// anyway, and after a subtree remap.
///
/// The JSON form on disk is unchanged (`{key: [ids]}`), so no stored index is
/// invalidated by either variant.
enum Postings {
    Owned {
        keys: Vec<u32>,
        /// `keys.len() + 1` entries; `off[0]` is always 0.
        off: Vec<u32>,
        ids: Vec<u32>,
    },
    Raw {
        /// Byte offset of the contiguous fixed-stride header table in `data`
        /// (NKGREP06). Entry `i` is `data[hdr + i*16 ..][..16]`, laid out
        /// `key | blen | last | blob_off`. Nothing per-run is
        /// materialized: `find` binary-searches keys in place and `ids_at`
        /// reads one entry then decodes that run's blob.
        hdr: usize,
        /// Number of header entries (postings) in the table.
        npost: usize,
        /// The mapped index file, so ids are never copied at load and a
        /// query faults in only the pages it actually reads.
        data: std::sync::Arc<memmap2::Mmap>,
        /// File count this index was built over. Layered: the load-time
        /// `last` check range-checks every run in O(runs) — a sequential scan
        /// of the table's `last` column, which the fixed stride makes
        /// cache-friendly — and `decode_run` range-checks every id as it is
        /// produced, which is the guard the subtree path relies on, since
        /// `into_owned` flattens runs without going through `intersect_all`.
        /// So no unchecked id reaches `is_cand` or `remap` on either path.
        nfiles: usize,
    },
}

impl Default for Postings {
    fn default() -> Self {
        Postings::Owned {
            keys: vec![],
            off: vec![0],
            ids: vec![],
        }
    }
}

impl Postings {
    /// Number of postings: one header entry each.
    fn npost(&self) -> usize {
        match self {
            Postings::Owned { keys, .. } => keys.len(),
            Postings::Raw { npost, .. } => *npost,
        }
    }
    /// Key of entry `i`. The owned form holds a `Vec`; the raw form reads the
    /// fixed-stride table in place, which is what lets load skip materializing
    /// one `Vec<u32>` per column.
    fn key_at(&self, i: usize) -> u32 {
        match self {
            Postings::Owned { keys, .. } => keys[i],
            Postings::Raw { hdr, data, .. } => {
                let at = hdr + i * POSTING_HDR;
                u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
            }
        }
    }
    /// One header field of entry `i`: `field` is 0 key, 1 blen, 2 last,
    /// 3 blob_off.
    fn hdr_at(&self, i: usize, field: usize) -> u32 {
        match self {
            Postings::Owned { .. } => unreachable!("owned postings have no header table"),
            Postings::Raw { hdr, data, .. } => {
                let at = hdr + i * POSTING_HDR + field * 4;
                u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
            }
        }
    }
    fn find(&self, k: u32) -> Option<usize> {
        match self {
            Postings::Owned { keys, .. } => keys.binary_search(&k).ok(),
            Postings::Raw { .. } => {
                // Keys are written strictly ascending, so a plain lower-bound
                // walk over the on-disk column is exact: O(log npost) reads of
                // 4 bytes instead of a materialized key vector.
                let (mut lo, mut hi) = (0usize, self.npost());
                while lo < hi {
                    let mid = lo + (hi - lo) / 2;
                    if self.key_at(mid) < k {
                        lo = mid + 1;
                    } else {
                        hi = mid;
                    }
                }
                (lo < self.npost() && self.key_at(lo) == k).then_some(lo)
            }
        }
    }
    /// Decode run `i`'s LEB128 deltas into `out`, range-checking each id as it
    /// is produced. The bounds live here rather than only at load so that no
    /// unchecked id can reach `is_cand` (rank) or `remap` (subtree), whatever
    /// a stored `last` claimed.
    fn decode_run(data: &[u8], at: usize, blen: usize, nfiles: usize, out: &mut Vec<u32>) {
        out.clear();
        // Bounded by `blen` rather than by a stored id count. Every delta is a
        // LEB128 varint of at least one byte, so consuming exactly `blen`
        // bytes yields exactly the ids a stored count would have named — which
        // is why the count is not in the header at all. A hostile `blen`
        // running past the end fails inside `get_varint` below rather than
        // asking for a huge allocation up front.
        let end = at.saturating_add(blen);
        out.reserve(blen.min(1 << 16));
        let mut prev = 0u32;
        let mut p = at;
        while p < end {
            let Some((d, next)) = get_varint(data, p) else {
                eprintln!(
                    "nkg: unreadable index (truncated posting run; rebuild with `nkg index`)"
                );
                std::process::exit(2);
            };
            p = next;
            let Some(id) = prev.checked_add(d) else {
                eprintln!("nkg: unreadable index (posting id overflow; rebuild with `nkg index`)");
                std::process::exit(2);
            };
            if id as usize >= nfiles {
                eprintln!(
                    "nkg: unreadable index (posting id out of range? rebuild with `nkg index`)"
                );
                std::process::exit(2);
            }
            prev = id;
            out.push(id);
        }
    }
    /// Ids of run `i`, decoded into `out` when they are still stored bytes.
    fn ids_at<'o>(&'o self, i: usize, out: &'o mut Vec<u32>) -> &'o [u32] {
        match self {
            Postings::Owned { off, ids, .. } => &ids[off[i] as usize..off[i + 1] as usize],
            Postings::Raw { data, nfiles, .. } => {
                let blen = self.hdr_at(i, 1) as usize;
                let blob_off = self.hdr_at(i, 3) as usize;
                Self::decode_run(data, blob_off, blen, *nfiles, out);
                out
            }
        }
    }
    /// Flatten to the owned form, so a subtree remap can rewrite ids in place.
    /// Range-checks as it decodes: this path never runs `ids_at`, and the
    /// remap indexes `remap[id]` directly, so an unchecked corrupt id here
    /// would panic rather than exit 2.
    fn into_owned(self) -> Postings {
        match self {
            owned @ Postings::Owned { .. } => owned,
            p @ Postings::Raw { .. } => {
                let Postings::Raw {
                    npost,
                    nfiles,
                    data,
                    ..
                } = &p
                else {
                    unreachable!("matched the Raw variant")
                };
                let (npost, nfiles) = (*npost, *nfiles);
                let mut keys = Vec::with_capacity(npost);
                let mut off = Vec::with_capacity(npost + 1);
                let mut ids = Vec::new();
                let mut run: Vec<u32> = Vec::new();
                off.push(0);
                for i in 0..npost {
                    let k = p.key_at(i);
                    let blen = p.hdr_at(i, 1) as usize;
                    let blob_off = p.hdr_at(i, 3) as usize;
                    Self::decode_run(data, blob_off, blen, nfiles, &mut run);
                    keys.push(k);
                    ids.extend_from_slice(&run);
                    off.push(ids.len() as u32);
                }
                Postings::Owned { keys, off, ids }
            }
        }
    }
    /// True when every posting id addresses a real file. This is the owned
    /// (JSON, and flattened-subtree) form's check. The binary form does not
    /// need it here: `parse_index_bin` validates every run's stored maximum
    /// during its single pass over the header table, so the loud exit 2 for a
    /// corrupt index still happens at load, whatever query arrives — and it
    /// happens once instead of twice.
    fn ids_in_range(&self, nfiles: usize) -> bool {
        match self {
            Postings::Owned { ids, .. } => ids.iter().all(|&id| (id as usize) < nfiles),
            Postings::Raw { npost, .. } => {
                // Field 2 is `last` under NKGREP06 (`key | blen | last |
                // blob_off`). Field 3, which the pre-bump code read, is
                // `blob_off` now and compares a byte offset against a file
                // count. Unreachable from the sole caller, which is
                // `parse_index` and deserializes through `FlatBuild` into
                // `Owned` only -- but kept correct rather than dropped, because
                // `true` would hand a future caller no check at all and the
                // arm's own doc claims one.
                (0..*npost).all(|i| (self.hdr_at(i, 2) as usize) < nfiles)
            }
        }
    }
}
impl Serialize for Postings {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let n = self.npost();
        let mut m = s.serialize_map(Some(n))?;
        let mut scratch: Vec<u32> = Vec::new();
        for i in 0..n {
            let run = self.ids_at(i, &mut scratch);
            m.serialize_entry(&self.key_at(i), run)?;
        }
        m.end()
    }
}

/// Deserialize into the flat form without materializing a `Vec` per posting:
/// each key's id run is appended straight into one buffer as it streams, and
/// the runs are ordered once at the end.
impl<'de> Deserialize<'de> for Postings {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_map(FlatPostingsVisitor)
    }
}

#[derive(Default)]
struct FlatBuild {
    /// (key, start, end) into `ids`, in the order the document listed them.
    entries: Vec<(u32, u32, u32)>,
    ids: Vec<u32>,
}

impl FlatBuild {
    /// Order the runs by key and lay them out contiguously. A duplicated key
    /// is a corrupt document, not a merge to resolve: concatenating the runs
    /// would hand rank an id list the file never described, and keeping only
    /// one would silently search less than a scan. Refuse instead, which
    /// `parse_index` turns into the usual loud exit 2.
    fn finish(mut self) -> Result<Postings, serde::de::value::Error> {
        self.entries.sort_by_key(|e| e.0);
        let mut keys: Vec<u32> = Vec::with_capacity(self.entries.len());
        let mut off: Vec<u32> = Vec::with_capacity(self.entries.len() + 1);
        let mut ids: Vec<u32> = Vec::with_capacity(self.ids.len());
        off.push(0);
        let mut last: Option<u32> = None;
        for &(k, s, e) in &self.entries {
            if last == Some(k) {
                return Err(serde::de::Error::custom("duplicate posting key"));
            }
            keys.push(k);
            off.push(off[off.len() - 1]);
            last = Some(k);
            ids.extend_from_slice(&self.ids[s as usize..e as usize]);
            *off.last_mut().unwrap() = ids.len() as u32;
        }
        Ok(Postings::Owned { keys, off, ids })
    }
}

struct FlatPostingsVisitor;
impl<'de> serde::de::Visitor<'de> for FlatPostingsVisitor {
    type Value = Postings;
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a postings map")
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut m: A) -> Result<Postings, A::Error> {
        let mut b = FlatBuild::default();
        while let Some(k) = m.next_key::<u32>()? {
            m.next_value_seed(FlatRunSeed { key: k, b: &mut b })?;
        }
        b.finish().map_err(serde::de::Error::custom)
    }
}

struct FlatRunSeed<'a> {
    key: u32,
    b: &'a mut FlatBuild,
}
impl<'de, 'a> serde::de::DeserializeSeed<'de> for FlatRunSeed<'a> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        struct RunVisitor<'a> {
            key: u32,
            b: &'a mut FlatBuild,
        }
        impl<'de, 'a> serde::de::Visitor<'de> for RunVisitor<'a> {
            type Value = ();
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a posting id list")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
                let start = self.b.ids.len() as u32;
                // size_hint is exact for a JSON array, so this reserves once.
                self.b.ids.reserve(seq.size_hint().unwrap_or(0));
                while let Some(id) = seq.next_element::<u32>()? {
                    self.b.ids.push(id);
                }
                let end = self.b.ids.len() as u32;
                self.b.entries.push((self.key, start, end));
                Ok(())
            }
        }
        d.deserialize_seq(RunVisitor {
            key: self.key,
            b: self.b,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct Index {
    /// Canonical absolute path of the tree the index was built from.
    /// Required: old absolute-path indexes without it fail to parse and are
    /// rejected loudly at load (rebuild with `nkg index`).
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
    postings: Postings,
}

/// Canonical absolute fingerprint of a build/query root; exit 2 when the
/// root does not resolve.
fn canon_root(root: &std::path::Path) -> PathBuf {
    match std::fs::canonicalize(root) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("nkg: bad root {}: {e}", root.display());
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

/// Stored `files` entries must be root-relative: absolute paths (stale
/// format) and `..` components (directory escape past the query root on
/// join) are refused loudly (exit 2), never silently dropped. Checked at
/// parse and again pre-join at load so a hostile index cannot make verify
/// read outside the rooted tree.
fn validate_stored_files(idx_path: &str, files: &[String]) {
    // An empty stored path is malformed in either form: `nkg index` never
    // emits one, and every output path derives from a real walk. Refusing it
    // here keeps it off the query path entirely.
    #[cfg(unix)]
    {
        // Byte-level equivalents of `PathBuf::from(p).is_absolute()` and
        // `components().any(ParentDir)`, with none of their cost. This runs
        // over every stored path on every query, so it is per-file work --
        // measured at 2.6 ms for 18k paths, nearly all of it two allocations
        // and a component parse that a byte scan replaces outright.
        //
        // Unix-only on purpose. On Windows an absolute path also has the
        // `C:\foo`, `\foo` and `\\server\share` forms, and `a/../b` is a
        // legal parent-dir reference written with a forward slash, so neither
        // check holds there and reimplementing that logic would be a way to
        // get the security guard subtly wrong.
        for p in files {
            let Some(first) = p.as_bytes().first() else {
                eprintln!("nkg: unreadable index {idx_path} (empty stored path)");
                std::process::exit(2);
            };
            if *first == b'/' {
                eprintln!("nkg: stale absolute-path index {idx_path}: rebuild with `nkg index`");
                std::process::exit(2);
            }
            if p.split('/').any(|seg| seg == "..") {
                eprintln!(
                    "nkg: hostile index {idx_path} (path escapes root {p:?}): rebuild with `nkg index`"
                );
                std::process::exit(2);
            }
        }
    }
    #[cfg(not(unix))]
    {
        use std::path::{Component, PathBuf};
        for p in files {
            if p.is_empty() {
                eprintln!("nkg: unreadable index {idx_path} (empty stored path)");
                std::process::exit(2);
            }
            let path = PathBuf::from(p);
            if path.is_absolute() {
                eprintln!("nkg: stale absolute-path index {idx_path}: rebuild with `nkg index`");
                std::process::exit(2);
            }
            if path.components().any(|c| matches!(c, Component::ParentDir)) {
                eprintln!(
                    "nkg: hostile index {idx_path} (path escapes root {p:?}): rebuild with `nkg index`"
                );
                std::process::exit(2);
            }
        }
    }
}

/// Index write that refuses symlink targets: a pre-check plus `O_NOFOLLOW`
/// open (unix) so a symlink swapped in between check and write still fails
/// loudly (exit 2) instead of writing through to the target.
fn write_index_file(idx_path: &str, bytes: &[u8]) {
    if let Ok(m) = std::fs::symlink_metadata(idx_path) {
        if m.file_type().is_symlink() {
            eprintln!("nkg: refusing to write index through symlink {idx_path}");
            std::process::exit(2);
        }
    }
    // Publish by rename, never by truncating the target in place. A reader
    // may hold the old index open (the query path maps it rather than copying
    // it), and truncating a mapped file underneath it faults with SIGBUS
    // instead of surfacing an error. Renaming a fully written sibling also
    // means a rebuild that dies partway leaves the previous index intact
    // rather than a torn one.
    let tmp_path = format!("{idx_path}.tmp{}", std::process::id());
    {
        use std::io::Write;
        #[cfg(unix)]
        let opts = {
            use std::os::unix::fs::OpenOptionsExt;
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create(true).truncate(true);
            o.custom_flags(libc::O_NOFOLLOW);
            o
        };
        #[cfg(not(unix))]
        let opts = {
            // The builder methods return `&mut Self`, so chaining them off
            // `OpenOptions::new()` binds a reference into a temporary that is
            // dropped at the end of the statement. Bind an owned value, as the
            // unix arm does.
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create(true).truncate(true);
            o
        };
        let write = || -> std::io::Result<()> {
            let mut f = opts.open(&tmp_path)?;
            f.write_all(bytes)?;
            f.sync_all()
        };
        if let Err(e) = write() {
            let _ = std::fs::remove_file(&tmp_path);
            eprintln!("nkg: cannot write index {idx_path}: {e}");
            std::process::exit(2);
        }
    }
    if let Err(e) = std::fs::rename(&tmp_path, idx_path) {
        let _ = std::fs::remove_file(&tmp_path);
        eprintln!("nkg: cannot write index {idx_path}: {e}");
        std::process::exit(2);
    }
}

/// Loud index refusal shared by every index loader (exit 2): `detail` is
/// the parenthesized cause (`"old format"`, `"truncated binary"`). One
/// short `eprintln!` site keeps the stderr bytes identical at every call
/// while fitting on a single line under every rustfmt version.
fn refuse_index(idx_path: &str, detail: &str, why: &dyn std::fmt::Display) -> ! {
    eprintln!("nkg: unreadable index {idx_path} ({detail}? rebuild with `nkg index`): {why}");
    std::process::exit(2);
}

/// Loud refusal for a stale binary index magic (exit 2), split out of
/// `parse_index_auto` for the same single-line-fits-everywhere reason.
fn refuse_stale_index(idx_path: &str) -> ! {
    // Derived from the constant, so a future format bump cannot leave the
    // message naming the previous magic.
    let want = String::from_utf8_lossy(BIN_MAGIC);
    eprintln!("nkg: stale index format {idx_path} (expected {want}): rebuild with `nkg index`");
    std::process::exit(2);
}

/// Parse index JSON; old absolute-path indexes (missing `root`) and corrupt
/// files are refused loudly instead of silently matching nothing.
fn parse_index(idx_path: &str, data: &str) -> Index {
    match serde_json::from_str::<Index>(data) {
        Ok(idx) => {
            validate_stored_files(idx_path, &idx.files);
            if !idx.postings.ids_in_range(idx.files.len()) {
                eprintln!("nkg: unreadable index {idx_path} (posting id out of range? rebuild with `nkg index`)");
                std::process::exit(2);
            }
            idx
        }
        Err(e) => refuse_index(idx_path, "old format", &e),
    }
}
/// Binary index magic (8 B) + plain-LE linear layout (NKGREP06):
/// magic | root_dev u64 | root_ino u64 | root_len u32 + root bytes
/// | nfiles u32 + (len u32 + bytes)*
/// | npostings u32
/// | header table: npostings x POSTING_HDR bytes, each
///     `key u32 | blen u32 | last u32 | blob_off u32`
/// | blob section: every run's LEB128 id deltas, concatenated at `blob_off`.
///
/// NKGREP04 splits the posting table into a contiguous fixed-stride header
/// array followed by one blob section. NKGREP03 interleaved each header with
/// its variable-length blob, so a run's byte offset had to be materialized as a
/// prefix sum at load: four `Vec<u32>` of one entry per posting. With the
/// headers contiguous and fixed-stride, a key lookup is a binary search
/// straight into the bytes and load allocates nothing per run. Storing
/// `blob_off` explicitly is what removes the prefix sum -- offsets are not
/// derivable by multiplication once blobs are concatenated.
///
/// Ids are delta-varint encoded: ids ascend inside a run, so a difference is
/// almost always one byte, which keeps a real-code index to a few MB. `blen`
/// lets the loader seek past a run without decoding it; `last` is the run's
/// maximum (ids ascend), so the load-time range check is one comparison per
/// run rather than decoding every delta -- and with the headers contiguous
/// that check is a sequential scan of `last` values, not a pointer chase.
///
/// NKGREP01-03 are refused loudly as stale (the generic `NKGREP` prefix check
/// covers them), same as a fingerprint mismatch. Keys are packed trigrams
/// (gram_pack), sorted numeric on write for stable bytes. Any truncation →
/// loud exit 2.
const BIN_MAGIC: &[u8; 8] = b"NKGREP06";
/// Bytes per posting header in the table NKGREP06 writes.
const POSTING_HDR: usize = 16;

/// LEB128 append. Ids ascend inside a run, so a plain unsigned delta needs no
/// zigzag: the writer only ever emits non-negative differences.
fn put_varint(out: &mut Vec<u8>, mut v: u32) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

/// LEB128 read at `at`; `Some((value, next_offset))` or `None` past the end,
/// on a continuation bit running off the slice, or on a value wider than
/// `u32`. That last case matters: accumulating in `u32` with `checked_shl`
/// validates the shift *amount* but not the bits it lands on, so a hostile
/// five-byte varint at shift 28 would silently drop everything above bit 31
/// and decode to a small, in-range id — wrong answers from a corrupt index
/// rather than a refusal.
fn get_varint(d: &[u8], at: usize) -> Option<(u32, usize)> {
    let mut v: u64 = 0;
    let mut shift = 0u32;
    let mut i = at;
    loop {
        let b = *d.get(i)?;
        v |= u64::from(b & 0x7f) << shift;
        if v > u64::from(u32::MAX) {
            return None;
        }
        i += 1;
        if b & 0x80 == 0 {
            return Some((v as u32, i));
        }
        shift += 7;
        if shift > 28 {
            return None;
        }
    }
}

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
    let npost = idx.postings.npost();
    put_u32(&mut out, npost as u32);
    // Header table, then blob section. `blob_off` is absolute from the start
    // of the file: the table's size is already fixed, so every blob's address
    // is known before the first header is written. Writing the table first is
    // what makes it a contiguous fixed-stride array the reader can binary
    // search and range-check in place, with nothing allocated per run.
    let blob_base = out.len() + npost * POSTING_HDR;
    let mut scratch: Vec<u32> = Vec::new();
    let mut run: Vec<u8> = Vec::new();
    let mut hdr: Vec<u8> = Vec::with_capacity(npost * POSTING_HDR);
    let mut blobs: Vec<u8> = Vec::new();
    for i in 0..npost {
        let ids = idx.postings.ids_at(i, &mut scratch);
        run.clear();
        let mut prev = 0u32;
        for id in ids {
            // Delta encoding assumes ids ascend. A hand-edited or hostile
            // index can break that, and `id - prev` would then underflow:
            // panic in debug, a silently huge varint in release. Refuse at
            // write time instead of emitting an unreadable .idx.bin.
            let Some(d) = id.checked_sub(prev) else {
                eprintln!(
                    "nkg: cannot encode index (posting ids not ascending); rebuild with `nkg index`"
                );
                std::process::exit(2);
            };
            put_varint(&mut run, d);
            prev = *id;
        }
        put_u32(&mut hdr, idx.postings.key_at(i));
        // No id count is stored: `blen` names the run's byte extent and every
        // delta is at least one varint byte, so the count is what the decoder
        // derives by consuming that extent. NKGREP05 carried it as a fifth
        // field, which made the header 20 bytes and the table 82% of a real
        // index.
        // `blen` lets the loader skip a run without decoding it, and `last`
        // lets it range-check one value per run (ids ascend, so `last` is the
        // run's maximum) instead of decoding every delta at load.
        put_u32(&mut hdr, run.len() as u32);
        put_u32(&mut hdr, ids.last().copied().unwrap_or(0));
        put_u32(&mut hdr, (blob_base + blobs.len()) as u32);
        blobs.extend_from_slice(&run);
    }
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&blobs);
    out
}

fn parse_index_bin(idx_path: &str, data: std::sync::Arc<memmap2::Mmap>) -> Index {
    let refuse = |why: &str| -> ! {
        refuse_index(idx_path, "truncated binary", &why);
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
    // NKGREP06: one contiguous fixed-stride header table, then the blob
    // section. Entry `i` is `key | blen | last | blob_off`, and
    // `blob_off` is absolute from the start of the file, so nothing here has
    // to be materialized to make a later lookup possible -- the loader hands
    // back the table's offset and the count, and `find` binary-searches the
    // keys in place.
    let hdr = cur;
    let table_end = hdr.saturating_add(npost.saturating_mul(POSTING_HDR));
    if table_end > data.len() {
        refuse("truncated posting header table");
    }
    // One sequential pass over the whole table, folding every load-time check
    // into it: strictly increasing keys (binary search needs that), every
    // run's stored maximum in range, and every blob offset addressing real
    // bytes. `chunks_exact` walks the fixed stride without recomputing an
    // index per entry, so this is a linear read over ~6 MB rather than a
    // pointer chase -- and it still makes a corrupt index a loud exit 2 at
    // load, whatever query arrives.
    let mut prev = 0u32;
    let mut first = true;
    // `chunks_exact` rather than `as_chunks`: the allow below is still
    // required, and `as_chunks` would hand the body a `&[u8; POSTING_HDR]`
    // instead of a slice, changing every index below for no gain.
    #[allow(clippy::chunks_exact_to_as_chunks)]
    for ent in data[hdr..table_end].chunks_exact(POSTING_HDR) {
        let k = u32::from_le_bytes(ent[0..4].try_into().unwrap());
        let blen = u32::from_le_bytes(ent[4..8].try_into().unwrap()) as usize;
        let last = u32::from_le_bytes(ent[8..12].try_into().unwrap());
        let blob_off = u32::from_le_bytes(ent[12..16].try_into().unwrap()) as usize;
        if !first && k <= prev {
            refuse("posting keys out of order");
        }
        first = false;
        prev = k;
        if (last as usize) >= nfiles {
            refuse("posting id out of range");
        }
        // The blob must lie inside the file. NKGREP03 walked every blob at load
        // and refused a bad length there; with stored `blob_off` nothing walks
        // them any more, so without this a hostile offset would only surface
        // inside `decode_run` -- and only for postings some query happens to
        // name. One comparison per entry keeps "any corrupt index is a loud
        // exit 2 regardless of query" true for NKGREP06 too.
        if blob_off.saturating_add(blen) > data.len() {
            refuse("bad posting length");
        }
    }
    let postings = Postings::Raw {
        hdr,
        npost,
        data,
        nfiles,
    };
    let idx = Index {
        root,
        root_dev,
        root_ino,
        files,
        postings,
    };
    validate_stored_files(idx_path, &idx.files);
    idx
}

/// Read raw index bytes once; binary (magic) vs JSON dispatch lives here so
/// both load helpers share it with unchanged signatures.
///
/// Hostile-index memory bound: an index file larger than
/// `MAX_INDEX_BYTES` refuses the whole operation loudly (exit 2, never a
/// silent truncation or per-file drop — either would break the
/// indexed==scan check by searching a subset while claiming the full
/// corpus). The read itself is length-capped so a file that grows past
/// the pre-check between metadata and read still cannot OOM the loader;
/// under-cap files take the identical bytes as before.
///
/// Deliberately NOT capped (documented refusal): per-corpus-file reads
/// (index build and verify) and hit/arena buffers. Any silent per-file
/// or per-hit cap would search less than the scan path and break equality
/// EQUAL; the user's own `--max-filesize` walk filter remains the
/// explicit, rg-compatible way to bound corpus reads.
const MAX_INDEX_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Map the index rather than reading it. A one-shot query needs the file
/// header, the file table and the posting entries its own trigrams name --
/// roughly the first 6 MB of a 35 MB index -- and never touches the blob
/// section holding the other 29 MB. Reading the whole file made load scale
/// with index size; mapping lets the kernel fault in only the pages used, so
/// load tracks the query instead of the corpus.
///
/// Safe against a concurrent rebuild because `write_index_file` publishes by
/// rename: the mapping keeps the old inode alive, so a reader sees either the
/// whole old index or the whole new one, and truncation can never reach
/// through the mapping to fault a live query with SIGBUS.
fn read_index_bytes(idx_path: &str) -> std::sync::Arc<memmap2::Mmap> {
    use memmap2::MmapOptions;
    let f = match std::fs::File::open(idx_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("nkg: cannot read index {idx_path}: {e}");
            std::process::exit(2);
        }
    };
    let len = match f.metadata() {
        Ok(m) => m.len(),
        Err(e) => {
            eprintln!("nkg: cannot read index {idx_path}: {e}");
            std::process::exit(2);
        }
    };
    if len > MAX_INDEX_BYTES {
        eprintln!("nkg: index {idx_path} exceeds 4 GiB: rebuild with `nkg index`");
        std::process::exit(2);
    }
    // mmap rejects a zero-length mapping, and an empty file is not an index.
    if len == 0 {
        eprintln!("nkg: unreadable index {idx_path} (empty): rebuild with `nkg index`");
        std::process::exit(2);
    }
    // SAFETY: the mapping is read-only and the file is opened read-only. The
    // only writer is `write_index_file`, which publishes by rename, so this
    // inode is never truncated or written while mapped.
    match unsafe { MmapOptions::new().len(len as usize).map(&f) } {
        Ok(m) => std::sync::Arc::new(m),
        Err(e) => {
            eprintln!("nkg: cannot map index {idx_path}: {e}");
            std::process::exit(2);
        }
    }
}
fn parse_index_auto(idx_path: &str, data: std::sync::Arc<memmap2::Mmap>) -> Index {
    if data.starts_with(BIN_MAGIC) {
        return parse_index_bin(idx_path, data);
    }
    if data.starts_with(b"NKGREP") {
        refuse_stale_index(idx_path);
    }
    match std::str::from_utf8(data.as_ref()) {
        Ok(s) => parse_index(idx_path, s),
        Err(e) => refuse_index(idx_path, "old format", &e),
    }
}
/// Index header (canonical `root` + its device/inode cookie) without
/// materializing `files` or `postings`. The serve-eligibility probe needs
/// only these three fields, and it runs before every cold query, so parsing
/// them off the full document paid a second ~7 ms index parse per query on a
/// 3k-file index. Every other key is skipped with `IgnoredAny`, which scans a
/// value without building it: no `files` strings, no `postings` map, no 459
/// id vectors. Breaking out of the map early is not an option — serde_json
/// rejects the unconsumed trailing comma, and skipping still validates the
/// whole document, so corruption stays a loud refusal.
fn index_header(idx_path: &str, data: &[u8]) -> (String, u64, u64) {
    if data.starts_with(BIN_MAGIC) {
        return parse_index_header_bin(idx_path, data);
    }
    if data.starts_with(b"NKGREP") {
        refuse_stale_index(idx_path);
    }
    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(e) => refuse_index(idx_path, "old format", &e),
    };
    use serde::de::{IgnoredAny, MapAccess, Visitor};
    struct HeaderVisitor;
    impl<'de> Visitor<'de> for HeaderVisitor {
        type Value = (String, u64, u64);
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("an index header object")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Self::Value, A::Error> {
            let (mut root, mut dev, mut ino) = (None, None, None);
            while let Some(k) = m.next_key::<&str>()? {
                match k {
                    "root" => root = Some(m.next_value()?),
                    "root_dev" => dev = Some(m.next_value()?),
                    "root_ino" => ino = Some(m.next_value()?),
                    _ => {
                        m.next_value::<IgnoredAny>()?;
                    }
                }
            }
            match (root, dev, ino) {
                (Some(r), Some(d), Some(i)) => Ok((r, d, i)),
                _ => Err(serde::de::Error::custom("index header field missing")),
            }
        }
    }
    let mut de = serde_json::Deserializer::from_str(s);
    match serde::Deserializer::deserialize_map(&mut de, HeaderVisitor) {
        Ok(v) => v,
        Err(e) => refuse_index(idx_path, "old format", &e),
    }
}

/// Binary header: magic | root_dev u64 | root_ino u64 | root_len u32 + bytes.
/// The `files`/`postings` tables that follow are never touched.
fn parse_index_header_bin(idx_path: &str, data: &[u8]) -> (String, u64, u64) {
    let mut cur = BIN_MAGIC.len();
    let mut take = |n: usize| -> &[u8] {
        let end = cur.saturating_add(n);
        if end > data.len() {
            refuse_index(idx_path, "truncated binary", &"header past end of file");
        }
        let s = &data[cur..end];
        cur = end;
        s
    };
    let dev = u64::from_le_bytes(take(8).try_into().unwrap());
    let ino = u64::from_le_bytes(take(8).try_into().unwrap());
    let n = u32::from_le_bytes(take(4).try_into().unwrap()) as usize;
    match std::str::from_utf8(take(n)) {
        Ok(r) => (r.to_owned(), dev, ino),
        Err(_) => refuse_index(idx_path, "truncated binary", &"non-utf8 root"),
    }
}

/// Read only the header prefix: `magic | root_dev u64 | root_ino u64 |
/// root_len u32 + root bytes`. The serve-eligibility probe needs exactly those
/// three fields, and pulling the whole index to get them doubled load on any
/// tree where a daemon has registered the file -- ~19 ms of a ~40 ms load on a
/// 34 MB real-code index, spent to learn a path.
fn read_index_header_bytes(idx_path: &str) -> Vec<u8> {
    use std::io::Read;
    let mut f = match std::fs::File::open(idx_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("nkg: cannot read index {idx_path}: {e}");
            std::process::exit(2);
        }
    };
    // magic(8) + root_dev(8) + root_ino(8) + root_len(4)
    const FIXED: usize = 28;
    let mut d = vec![0u8; FIXED];
    if let Err(e) = f.read_exact(&mut d) {
        eprintln!("nkg: unreadable index {idx_path}: {e}");
        std::process::exit(2);
    }
    // Bound `root_len` against the REAL file length, not MAX_INDEX_BYTES. A
    // corrupt index carrying root_len = 0xFFFF_FFFF passes a 4 GiB ceiling and
    // would ask for a 4 GiB allocation to hold a path. `str_at` refused against
    // `data.len()`, so this keeps that property on the cheaper read.
    let root_len = u32::from_le_bytes(d[24..28].try_into().unwrap()) as usize;
    let file_len = f.metadata().map(|m| m.len() as usize).unwrap_or(0);
    if root_len > file_len.saturating_sub(FIXED) {
        eprintln!("nkg: unreadable index {idx_path}: bad root length");
        std::process::exit(2);
    }
    let start = d.len();
    d.resize(start + root_len, 0);
    if let Err(e) = f.read_exact(&mut d[start..]) {
        eprintln!("nkg: unreadable index {idx_path}: {e}");
        std::process::exit(2);
    }
    d
}

fn serve_eligible_root(idx_path: &str, query_root: &std::path::Path) -> bool {
    // No sidecar means no daemon ever registered this index, so the serve
    // probe cannot hit and the answer is already false. Returning here skips
    // reading and header-scanning the index on every cold query — a ~12 ms
    // scan on a real-code JSON index — and costs nothing: the root checks
    // below also live in `load_index_for_query`, which refuses a mismatch
    // with the same message and exit 2 the moment we fall through to it.
    if !PathBuf::from(serve_info_path(idx_path)).exists() {
        return false;
    }
    let data = read_index_header_bytes(idx_path);
    let (root, root_dev, root_ino) = index_header(idx_path, &data);
    let q_canon = canon_root(query_root);
    let idx_canon = canon_root(&PathBuf::from(&root));
    let rel = match q_canon.strip_prefix(&idx_canon) {
        Ok(r) => r.to_owned(),
        Err(_) => {
            eprintln!(
                "nkg: index root mismatch (built at {}, queried at {})",
                root,
                q_canon.display()
            );
            std::process::exit(2);
        }
    };
    let (dev, ino) = root_cookie(&idx_canon);
    if (dev, ino) != (root_dev, root_ino) {
        eprintln!(
            "nkg: index root mismatch (built at {}, queried at {}: root replaced)",
            root,
            q_canon.display()
        );
        std::process::exit(2);
    }
    rel.as_os_str().is_empty()
}

/// Load an index for a query rooted at `query_root`: refuse (exit 2) when
/// the query root lies outside the index root, then keep only entries under
/// the query root and materialize them to query-root-joined paths so
/// rank/verify see scan-identical strings.
fn load_index_for_query(idx_path: &str, query_root: &std::path::Path) -> Index {
    let data = read_index_bytes(idx_path);
    let mut idx = parse_index_auto(idx_path, data);
    let q_canon = canon_root(query_root);
    let idx_base = PathBuf::from(&idx.root);
    let idx_canon = canon_root(&idx_base);
    let rel = match q_canon.strip_prefix(&idx_canon) {
        Ok(r) => r.to_owned(),
        Err(_) => {
            eprintln!(
                "nkg: index root mismatch (built at {}, queried at {})",
                idx.root,
                q_canon.display()
            );
            std::process::exit(2);
        }
    };
    let (dev, ino) = root_cookie(&idx_canon);
    if (dev, ino) != (idx.root_dev, idx.root_ino) {
        eprintln!(
            "nkg: index root mismatch (built at {}, queried at {}: root replaced)",
            idx.root,
            q_canon.display()
        );
        std::process::exit(2);
    }
    validate_stored_files(idx_path, &idx.files);
    // Narrow to the queried subtree: stored paths are index-root-relative,
    // so drop entries outside the query root and re-base the survivors onto
    // it (`query_root.join(suffix)` echoes the argv prefix like a scan).
    // Postings hold file ids, so remap them alongside the filter.
    //
    // The common case is a root query with a `.` root, and there the rebuild
    // is the identity: `"./".join(f)` strips back to exactly `f`, so `kept`
    // equals `idx.files` and `remap` maps every id to itself. Doing it anyway
    // costs a `join`, a `to_string_lossy` and two `String` allocations per
    // stored file -- ~37k allocations on an 18k-file index, measured at
    // several milliseconds of a ~10 ms load. Skip it; the subtree branch
    // below is the only one that needs either.
    // Empty unless the rebuild below runs, and only the subtree branch reads
    // it -- which is exactly the case where the rebuild runs.
    let mut remap: Vec<Option<u32>> = Vec::new();
    // An empty stored path would take the `query_root` arm and yield "."
    // where skipping yields "", so `validate_stored_files` refuses one at load
    // (both index formats) rather than this loop having to check every path on
    // every query.
    if !(rel.as_os_str().is_empty() && query_root == std::path::Path::new(".")) {
        remap.resize(idx.files.len(), None);
        let mut kept = Vec::with_capacity(idx.files.len());
        for (id, f) in idx.files.iter().enumerate() {
            let suffix = if rel.as_os_str().is_empty() {
                f.clone()
            } else {
                match std::path::Path::new(f).strip_prefix(&rel) {
                    Ok(s) => s.to_string_lossy().into_owned(),
                    Err(_) => continue,
                }
            };
            // rg parity (audit #10): `query_root.join(rel)` echoes the argv
            // prefix (`.` -> `./src/a.txt`); strip one leading `./` so cold
            // indexed prints `src/a.txt` like rg and like the serve wire.
            // SHAPE CHANGE: indexed JSON/text paths with a `.` root lose `./`.
            let joined = if suffix.is_empty() {
                query_root.to_string_lossy().into_owned()
            } else {
                query_root.join(&suffix).to_string_lossy().into_owned()
            };
            remap[id] = Some(kept.len() as u32);
            kept.push(strip_dot_slash(&joined).to_owned());
        }
        idx.files = kept;
    }
    // An exact-root query keeps every stored path at its own id, so `remap`
    // is the identity: the postings pass below would rewrite each of ~740k
    // ids to itself and drop nothing. Subtree queries still filter and
    // renumber, which is the only case that needs it.
    if !rel.as_os_str().is_empty() {
        // Subtree queries renumber ids, so a raw run is flattened once here;
        // the exact-root path above never pays for it.
        let Postings::Owned {
            keys: old_keys,
            off: old_off,
            ids: old_ids,
        } = std::mem::take(&mut idx.postings).into_owned()
        else {
            unreachable!("into_owned always yields the owned form")
        };
        let mut keys: Vec<u32> = Vec::with_capacity(old_keys.len());
        let mut off: Vec<u32> = vec![0];
        let mut ids: Vec<u32> = Vec::with_capacity(old_ids.len());
        for (i, k) in old_keys.iter().enumerate() {
            let before = ids.len();
            for &id in &old_ids[old_off[i] as usize..old_off[i + 1] as usize] {
                if let Some(n) = remap[id as usize] {
                    ids.push(n);
                }
            }
            // A run emptied by the subtree filter keeps no key, matching the
            // `retain(|_, ids| !ids.is_empty())` this replaces.
            if ids.len() != before {
                keys.push(*k);
                off.push(ids.len() as u32);
            }
        }
        idx.postings = Postings::Owned { keys, off, ids };
    }
    idx
}

/// Load an index for `serve`: no query root exists, so the stored canonical
/// root is the verify base. Refuse (exit 2) when the tree moved or was
/// replaced behind the stored fingerprint.
fn load_index_for_serve(idx_path: &str) -> Index {
    let data = read_index_bytes(idx_path);
    let mut idx = parse_index_auto(idx_path, data);
    let base = PathBuf::from(&idx.root);
    let live = canon_root(&base);
    let (dev, ino) = root_cookie(&live);
    if live.to_string_lossy() != idx.root || (dev, ino) != (idx.root_dev, idx.root_ino) {
        eprintln!(
            "nkg: index root mismatch (built at {}, now at {})",
            idx.root,
            live.display()
        );
        std::process::exit(2);
    }
    validate_stored_files(idx_path, &idx.files);
    for f in idx.files.iter_mut() {
        *f = base.join(&*f).to_string_lossy().into_owned();
    }
    idx
}

/// Traversal filters (rg-compatible shapes): `--hidden`, `--no-ignore`,
/// `-L/--follow`, `-g/--glob`, `-d/--max-depth`, `--max-filesize`.
/// Default holds historical behavior: hidden skipped, ignore files
/// respected, links unfollowed, unbounded depth/size, no globs.
#[derive(Default)]
struct WalkOptions {
    hidden: bool,
    no_ignore: bool,
    follow: bool,
    max_depth: Option<usize>,
    max_filesize: Option<u64>,
    globs: Vec<String>,
}

/// Loud refusal for an unparsable `--max-filesize` value (exit 2 via
/// `usage`): keeps the long `eprintln!` at a shallow indent so it fits on
/// one line under every rustfmt version; stderr bytes are unchanged.
fn refuse_bad_filesize(arg: &str) -> ! {
    eprintln!("nkg: bad --max-filesize {arg:?}: expected bytes with optional K/M/G suffix");
    usage();
}

/// `--max-filesize` human size: plain bytes or a K/M/G suffix (powers of
/// 1024, either case — probed live against rg 15.1.0: `1K` keeps a 1010 B
/// file). None on garbage; the caller exits 2 like rg's `invalid size`.
fn parse_filesize(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let (num, mult) = match s.chars().last().unwrap() {
        'K' | 'k' => (&s[..s.len() - 1], 1024u64),
        'M' | 'm' => (&s[..s.len() - 1], 1024 * 1024),
        'G' | 'g' => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        c if c.is_ascii_digit() => (s, 1),
        _ => return None,
    };
    num.parse::<u64>().ok()?.checked_mul(mult)
}

fn walk_files(root: &PathBuf, opts: &WalkOptions) -> (Vec<PathBuf>, bool) {
    // Paths come back sorted. Two callers depend on this: the index mints file ids
    // from the returned order, and a stable score sort breaks ties BY ID, so
    // readdir order leaked into output. It is also filesystem-specific -- APFS
    // returns directory entries in insertion order and ext4 in hash order -- so the
    // same corpus ranked equal-scored files differently per filesystem. Sorting
    // here rather than at one call site keeps the index and scan walks in the same
    // order, which is what the indexed==scan oracle compares.

    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(!opts.hidden)
        .git_ignore(!opts.no_ignore)
        .ignore(!opts.no_ignore)
        .git_global(!opts.no_ignore)
        .git_exclude(!opts.no_ignore)
        .parents(true)
        .require_git(false)
        .follow_links(opts.follow);
    if let Some(d) = opts.max_depth {
        builder.max_depth(Some(d));
    }
    // -g/--glob runs in `filter_entry`, NOT `builder.overrides`: probed rg
    // 15.1.0 keeps gitignore above -g whitelists (a gitignored file matching
    // `-g '*.txt'` is still skipped), while builder-level overrides would
    // whitelist it past gitignore ("overrides have the highest precedence").
    // The walker's own ignore machinery runs first, so gitignore still wins
    // and the Override only further restricts. Same matcher, same input
    // (leading `./` stripped exactly as dir.rs feeds it): bare globs
    // whitelist, `!` globs exclude, neg-only keeps everything else, dirs
    // never prune traversal on a non-match.
    let mut glob_matcher: Option<ignore::overrides::Override> = None;
    if !opts.globs.is_empty() {
        let mut ob = OverrideBuilder::new(root);
        for g in &opts.globs {
            if let Err(e) = ob.add(g) {
                eprintln!("nkg: bad --glob {g:?}: {e}");
                std::process::exit(2);
            }
        }
        match ob.build() {
            Ok(ov) => glob_matcher = Some(ov),
            Err(e) => {
                eprintln!("nkg: bad --glob: {e}");
                std::process::exit(2);
            }
        }
    }
    // rg parity (probed 15.1.0): `.git/` never descends unless --no-ignore:
    // --hidden alone still skips it; --hidden+--no-ignore searches it. No
    // git ops involved: pure path-component prune in filter_entry. Pruning
    // the `.git` dir entry itself kills descent, so pack files cost nothing.
    let skip_git = !opts.no_ignore;
    if glob_matcher.is_some() || opts.max_filesize.is_some() || skip_git {
        let root_path = root.clone();
        let max_opt = opts.max_filesize;
        builder.filter_entry(move |e| {
            // Explicit file operands bypass traversal filters (probed rg:
            // -g, -d, hidden, and --max-filesize all still search them).
            if e.path() == root_path {
                return true;
            }
            let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if skip_git {
                // Relative to the walk root so an explicit `.git` operand
                // still searches (probed: `rg --hidden pat .git` does). A
                // plain file named `.git` (worktree pointer) is a hidden
                // file, not a tree: searched under --hidden, never pruned.
                if let Ok(rel) = e.path().strip_prefix(&root_path) {
                    let mut comps = rel.components().peekable();
                    while let Some(c) = comps.next() {
                        let last = comps.peek().is_none();
                        if c.as_os_str() == ".git" && (!last || is_dir) {
                            return false;
                        }
                    }
                }
            }
            if let Some(max) = max_opt {
                // Files only: dir metadata lengths are filesystem noise —
                // filtering them would prune whole subtrees (probed: rg
                // keeps subdir files under --max-filesize 100).
                if !is_dir && e.metadata().map(|m| m.len() > max).unwrap_or(false) {
                    return false;
                }
            }
            match &glob_matcher {
                Some(ov) => {
                    let p = e.path();
                    let rel = p.strip_prefix("./").unwrap_or(p);
                    !ov.matched(rel, is_dir).is_ignore()
                }
                None => true,
            }
        });
    }
    let mut paths: Vec<PathBuf> = vec![];
    let mut had_error = false;
    for entry in builder.build() {
        match entry {
            Ok(e) => {
                if e.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    paths.push(e.path().to_path_buf());
                }
            }
            Err(e) => {
                eprintln!("nkg: walk error: {e}");
                had_error = true;
            }
        }
    }
    paths.sort();
    (paths, had_error)
}

/// Label for the single stdin search unit (`-` operand or piped stdin with
/// no path). Chosen over rg's `<stdin>` for shell-visibility; the `-c`
/// shape stays `label:count` and `-l` prints the bare label.
const STDIN_LABEL: &str = "(standard input)";

/// verbatim-banked ColCollector as `verify_one_raw`, but over an
/// already-read stdin buffer instead of a file path. Empty/binary buffers
/// hold no matches, mirroring the file path (binaries are skipped on both
/// index and verify sides). Own TLS Searcher: no shared fn is changed.
/// Scores fold path_bonus 0 / depth 0; the label comes from the ptab.
/// Frozen stdin wrapper (same wrapper contract as `verify_one_raw`): the
/// body lives in `search_stdin_raw_inv` with `invert = false`.
fn search_stdin_raw(buf: &[u8], matcher: &RegexMatcher) -> Option<FileHits> {
    search_stdin_raw_inv(buf, matcher, false)
}

/// Stdin slice-search with MatchFlags invert: same contract as
/// `verify_one_raw_ctx`'s invert (local inverted searcher per call).
fn search_stdin_raw_inv(buf: &[u8], matcher: &RegexMatcher, invert: bool) -> Option<FileHits> {
    use std::cell::RefCell;
    thread_local! {
        static SEARCHER: RefCell<Searcher> = RefCell::new(SearcherBuilder::new().build());
    }
    if buf.is_empty() {
        return None;
    }
    if is_binary(buf) {
        return None;
    }
    let mut sink = ColCollector {
        arena: vec![],
        metas: vec![],
        path_bonus: 0.0,
        match_limit: None,
    };
    let ok = SEARCHER.with(|s| {
        let mut local: Option<Searcher> = None;
        let mut normal = s.borrow_mut();
        if invert {
            local = Some(SearcherBuilder::new().invert_match(true).build());
        }
        let searcher: &mut Searcher = match local.as_mut() {
            Some(inv) => inv,
            None => &mut normal,
        };
        searcher.search_slice(matcher, buf, &mut sink).is_ok()
    });
    if ok && !sink.metas.is_empty() {
        Some(FileHits {
            pid: 0,
            arena: sink.arena,
            metas: sink.metas,
            line_starts: vec![],
        })
    } else {
        None
    }
}

/// Display-path normalization (rg parity, probed 15.1.0): strip a single
/// leading `./` so `nkg pat .` prints `src/a.txt`, not `./src/a.txt`.
/// Absolute paths and bare relatives pass through untouched.
fn strip_dot_slash(s: &str) -> &str {
    s.strip_prefix("./").unwrap_or(s)
}
/// Serve-wire display path: index-root-relative form of an absolute
/// daemon path (`<root>/<rel>` -> `<rel>`). Falls back to the absolute
/// string when it escapes the root (should not happen; fail-open display).
fn serve_display_path<'a>(abs: &'a str, root: &str) -> &'a str {
    let prefix = root.strip_suffix('/').unwrap_or(root);
    if let Some(rest) = abs.strip_prefix(prefix) {
        if let Some(rel) = rest.strip_prefix('/') {
            if !rel.is_empty() {
                return rel;
            }
        }
    }
    // Fallback: Path-prefix comparison covers symlinked/macOS /private
    // aliasing where string prefixes diverge but components agree.
    if let Ok(rel) = std::path::Path::new(abs).strip_prefix(std::path::Path::new(root)) {
        if let Some(s) = rel.to_str() {
            if !s.is_empty() {
                // Leak-free: the stripped `rel` borrows `abs`, but `to_str`
                // on the stripped path borrows the intermediate; re-slice
                // `abs` by length so the return borrows `abs` directly.
                let off = abs.len() - s.len();
                return &abs[off..];
            }
        }
    }
    abs
}
/// Distinct matched-file count from a ranked order (`ord` + `loc`): the
/// `F` in `N matches in F files` counts files with hits, not files walked.
fn matched_file_count(ord: &[u32], loc: &[(u32, u32)]) -> usize {
    let mut seen: HashSet<u32> = HashSet::with_capacity(ord.len().min(1024));
    for &i in ord {
        seen.insert(loc[i as usize].0);
    }
    seen.len()
}
/// `-c` / `-l` line writer: `path:count` per matching file, or matching
/// paths only when `files_only` (`-l` wins over `-c`, matching rg:
/// `--files-with-matches` overrides `--count`). Rows must arrive path-sorted
/// from the caller. Zero-count files are omitted — rg prints `:0` rows, a
/// deliberate deviation keeping indexed==scan identical (binaries, candidates)
/// with stable order; the `path:count` shape itself is rg-compatible.
fn write_aggregates(w: &mut impl Write, rows: &[(&str, usize)], files_only: bool) {
    let mut buf = Vec::with_capacity(rows.len() * 64);
    for (p, n) in rows {
        buf.extend_from_slice(p.as_bytes());
        if !files_only {
            buf.push(b':');
            buf.extend_from_slice(n.to_string().as_bytes());
        }
        buf.push(b'\n');
    }
    stdout_write_all(w, &buf);
}

/// Identical binary-file skip on both index and verify sides (soundness):
/// a file is binary when its first 8192 bytes contain a NUL. `cmd_index`
/// and every verify path share this predicate so indexed==scan on binaries.
/// `memchr` rather than a byte loop: the scalar `iter().any` scanned the
/// same 8 KiB head of every file one byte at a time and measured 5.2 ms over
/// a 2k-file tree against 0.2 ms here — most of what separated the scan path
/// from ripgrep once the open/read cost was subtracted.
fn is_binary(bytes: &[u8]) -> bool {
    memchr::memchr(0, &bytes[..bytes.len().min(8192)]).is_some()
}

/// Multiply-xorshift finalizer for the build's gram set. A gram key is a
/// packed byte window that is already close to its own hash, so SipHash-1-3's
/// key mixing buys nothing here and lands on the index build's hottest loop
/// (every window of every file hashes once). The xorshift-multiply rounds are
/// what makes the TOP 7 bits vary: hashbrown derives its bucket from the low
/// bits and its control byte from the top 7, and a bare multiply leaves the
/// top bits of a 32-bit input zero.
#[derive(Default)]
struct GramHasher(u64);

impl std::hash::Hasher for GramHasher {
    fn write(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0 = (self.0 ^ *b as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        }
    }

    fn write_u32(&mut self, n: u32) {
        self.0 = (n as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }

    fn finish(&self) -> u64 {
        let mut h = self.0;
        h ^= h >> 32;
        h = h.wrapping_mul(0xD6E8_FEB8_6659_FD93);
        h ^= h >> 32;
        h
    }
}

type GramSet = HashSet<u32, std::hash::BuildHasherDefault<GramHasher>>;

/// Distinct grams of BOTH widths in one set, packed into the same `u32` key
/// space. The widths are kept disjoint by construction rather than by a tag
/// bit: a trigram packs into 24 bits with the top byte always zero, a
/// four-gram uses all 32, and a four-gram whose first byte is NUL is skipped
/// (that is a binary file, which is never indexed anyway). So every 3-gram key
/// is < 2^24 and every 4-gram key is >= 2^24, and one sorted key table holds
/// both without collisions.
fn grams_of(bytes: &[u8]) -> GramSet {
    let mut set: GramSet = Default::default();
    let n = bytes.len();
    if n < 3 {
        return set;
    }
    if n == 3 {
        set.insert(((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32);
        return set;
    }
    // One pass for both widths. Two `windows` walks read the whole buffer
    // twice and insert about 38 million times over 19 MB of source; deriving
    // the trigram from the same window as the four-gram halves the memory
    // traffic without changing which grams are produced.
    for w in bytes.windows(4) {
        let (a, b, c, d) = (w[0], w[1], w[2], w[3]);
        set.insert(((a as u32) << 16) | ((b as u32) << 8) | c as u32);
        if a == 0 {
            continue;
        }
        set.insert(((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | d as u32);
    }
    // The final three bytes form a trigram no four-byte window can reach.
    set.insert(((bytes[n - 3] as u32) << 16) | ((bytes[n - 2] as u32) << 8) | bytes[n - 1] as u32);
    set
}

#[cfg(test)]
mod gram_hash_tests {
    use super::GramHasher;
    use std::hash::Hasher;

    /// hashbrown picks the bucket from the low bits and the control byte from
    /// the TOP 7, and packed 4-grams leave the top half of a plain multiply
    /// zero. Assert the high bits actually move for a dense run of real gram
    /// keys, so a retuned constant cannot silently re-bury them (that costs
    /// correctness nothing and build time ~10x).
    #[test]
    fn gram_hash_spreads_the_top_control_bits() {
        let mut seen = std::collections::HashSet::new();
        for key in (0u32..4096).map(|k| 0x0100_0000u32 | k) {
            let mut h = GramHasher::default();
            h.write_u32(key);
            seen.insert((h.finish() >> 57) as u8);
        }
        assert!(
            seen.len() >= 100,
            "only {} of 128 control tags used",
            seen.len()
        );
    }
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
        // Soundness fallback: `(?` changes literal semantics (flags `(?i)`,
        // groups `(?P<>)`, comments `(?#)`, lookaround) and `{n}`/`*`/`?`
        // can drop a required trigram (`ABCDEF{0}` matches `ABCDE`, which
        // lacks `DEF`; `NEEDLE_ALPHA?` matches `NEEDLE_ALPH`, lacking `PHA`).
        // Any of them forces a full scan; `+` keeps every literal run.
        if branch_needs_fallback(&branch) {
            return None;
        }
        let mut ands = HashSet::new();
        for run in literal_runs(&branch) {
            if run.len() >= 4 {
                // A run of four or more bytes yields four-grams. Intersecting
                // them is far more selective than three-grams alone, because
                // the file must hold the run's bytes adjacently rather than
                // merely contain each gram somewhere -- which is the whole
                // gap against an index that enforces adjacency.
                for w in run.windows(4) {
                    if w[0] == 0 {
                        continue;
                    }
                    ands.insert(
                        ((w[0] as u32) << 24)
                            | ((w[1] as u32) << 16)
                            | ((w[2] as u32) << 8)
                            | (w[3] as u32),
                    );
                }
            } else if run.len() == 3 {
                // Too short for a four-gram; the three-gram is still required.
                ands.insert(gram_pack(&[run[0], run[1], run[2]]));
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

/// True when a split branch contains an unescaped `(?` (flags, named groups,
/// comments, lookaround), an unescaped `{`+digit repetition, or an unescaped
/// `*`/`?` quantifier outside a `[...]` class. Each can drop a required
/// trigram (`ABCDEF{0}` matches `ABCDE` which lacks `DEF`; `NEEDLE_ALPHA?`
/// matches `NEEDLE_ALPH` which lacks `PHA`), so any of them forces a full
/// scan. `+` stays indexed: it keeps at least one copy of its atom, so every
/// match still contains the literal run. Escapes and class contents are
/// skipped exactly as `literal_runs` skips them, so an escaped/literal
/// `(?`, `{2}`, `*`, or `?` never forces a fallback it does not need.
fn branch_needs_fallback(branch: &str) -> bool {
    let mut it = branch.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\\' => {
                let _ = it.next();
            }
            '[' => {
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
            '(' => {
                if it.peek() == Some(&'?') {
                    return true;
                }
            }
            '*' | '?' => return true,
            '{' if it.peek().is_some_and(|p| p.is_ascii_digit()) => return true,
            '{' => {}
            _ => {}
        }
    }
    false
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
            // Punctuation is literal in a regex, so it continues the run instead
            // of breaking it: `Result<T, E>` must yield the cross-boundary
            // trigrams `lt<`, `t<T`, `<T,`, `T<,`, `T, `, `, E`, ` E>` as
            // well as `res`..`ult`. Those are far rarer than the alnum-only
            // grams and cut the verified candidate set sharply.
            //
            // EVERY metacharacter must break a run, quantifiers included: a
            // required trigram has to appear in every match, and `AB+C` matches
            // `ABC`, so a run of `AB+C` would demand `AB+` and silently skip
            // the match. `branch_needs_fallback` screens `*`, `?` and `{`,
            // but it deliberately lets `+` through (`+` preserves the literal
            // run, which mattered when only alnum bytes formed runs). The list
            // is therefore complete rather than filtered by what upstream
            // happens to reject. `[` and `\` are consumed by the arms above;
            // a bare `]` cannot start a class, so it breaks here. `|` is split
            // into branches upstream but is listed anyway so the set stays
            // complete if that ever changes.
            '.' | '^' | '$' | '*' | '+' | '?' | '(' | ')' | ']' | '{' | '}' | '|' => {
                if !cur.is_empty() {
                    runs.push(std::mem::take(&mut cur));
                }
            }
            c if (c as u32) < 128 => cur.push(c as u8),
            // Non-ASCII: a byte-level trigram over its UTF-8 form is not a
            // substring the index can be asked for, so keep the old behavior.
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

/// Matcher construction: ASCII-gated fast path (V1) plus the `-i` gate.
/// Default (`case_insensitive=false`) is the exact V1 sequence: ASCII
/// patterns skip the Unicode tables (`unicode(false)` + `\n` line
/// terminator, unlocking the fast line-oriented path) and pure literals add
/// `fixed_strings`; each keeps independently, builder errors retry
/// less-gated down to plain `RegexMatcher::new`, so construction never
/// fails where it used to work.
/// `-i` keeps the Unicode tables on purpose: `case_insensitive(true)` with
/// Unicode is full simple-fold insensitivity (ripgrep-compatible: `hello`
/// finds `HELLO`, `café` finds `CAFÉ`), while adding `unicode(false)`
/// would shrink folding to ASCII only. The cost is the Unicode tables on
/// `-i` queries alone; the default path is untouched. `fixed_strings` still
/// applies to pure literals (the engine folds literals itself). The final
/// fallback keeps `case_insensitive(true)` so `-i` never silently degrades
/// to case-sensitive; a truly bad pattern still returns Err (exit 2).
fn build_matcher(pattern: &str, case_insensitive: bool) -> Result<RegexMatcher, grep_regex::Error> {
    let ascii_only = pattern.is_ascii() && !case_insensitive;
    let literal_only = is_pure_literal(pattern);
    if case_insensitive || ascii_only || literal_only {
        let mut b = RegexMatcherBuilder::new();
        if case_insensitive {
            b.case_insensitive(true);
        }
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
        if case_insensitive {
            let mut bi = RegexMatcherBuilder::new();
            bi.case_insensitive(true);
            if let Ok(m) = bi.build(pattern) {
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
/// MatchFlags (-m/-e/-f/-F/-v/-w): multi-pattern + matcher-flag layer.
/// Shapes probed against rg 15.1.0; deviations noted inline.
///
/// Patterns arrive as a list (positional, `-e` repeats, `-f` lines). The
/// matcher sees one alternation; the prefilter sees per-pattern branches.
fn regex_escape_into(out: &mut String, s: &str) {
    // Escape set for regex-syntax: every other byte (incl. multibyte UTF-8)
    // passes through verbatim.
    for c in s.chars() {
        if matches!(
            c,
            '\\' | '.'
                | '+'
                | '*'
                | '?'
                | '('
                | ')'
                | '|'
                | '['
                | ']'
                | '{'
                | '}'
                | '^'
                | '$'
                | '#'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
}

/// Combine CLI patterns into one alternation. Every branch is wrapped in
/// `(?:...)` so inline flags (`(?i)`) stay scoped to their own pattern —
/// rg 15.1.0 does not leak flags across `-e` (probed) — and an inner `|`
/// can never merge branches (a naive join would split `(a|b)|c` into
/// `(a`, `b)`, `c`, requiring `a` of every match: unsound). Fixed mode
/// pre-escapes each pattern so the combined string stays a plain regex
/// alternation (`fixed_strings` would treat the separators literally).
fn combine_patterns(patterns: &[String], fixed: bool) -> String {
    // A lone pattern needs no alternation: return it verbatim. (Wrapping a
    // single fixed pattern in `(?:...)` would make `fixed_strings` search
    // for the wrappers literally.)
    if patterns.len() == 1 {
        return patterns[0].clone();
    }
    let mut out = String::new();
    for (k, p) in patterns.iter().enumerate() {
        if k > 0 {
            out.push('|');
        }
        out.push_str("(?:");
        if fixed {
            regex_escape_into(&mut out, p);
        } else {
            out.push_str(p);
        }
        out.push(')');
    }
    out
}

/// Extended matcher entry: `word` adds word-boundary matching and keeps the
/// Unicode tables on (the ASCII `unicode(false)` gate would shrink
/// boundaries to ASCII, but rg 15.1.0 treats é as a word char — probed:
/// `-w foo` skips `fooé` yet takes `foo-bar`); `fixed` treats the pattern
/// literally (callers pass it only for a single pattern; multi-pattern
/// fixed arrives pre-escaped via `combine_patterns`). With both unset this
/// delegates to `build_matcher` exactly, so the default path is untouched
/// by construction.
fn build_matcher_opts(
    pattern: &str,
    case_insensitive: bool,
    word: bool,
    fixed: bool,
) -> Result<RegexMatcher, grep_regex::Error> {
    if !word && !fixed {
        return build_matcher(pattern, case_insensitive);
    }
    let ascii_only = pattern.is_ascii() && !case_insensitive && !word;
    let mut b = RegexMatcherBuilder::new();
    if case_insensitive {
        b.case_insensitive(true);
    }
    if word {
        b.word(true);
    }
    if ascii_only {
        b.unicode(false);
        b.line_terminator(Some(b'\n'));
    }
    if fixed {
        b.fixed_strings(true);
    }
    if let Ok(m) = b.build(pattern) {
        return Ok(m);
    }
    // Same less-gated retries as `build_matcher`, each keeping word+fixed
    // so a retry never silently drops them; the final fallback keeps them
    // too, and a truly bad pattern still returns Err (exit 2).
    if ascii_only {
        let mut bz = RegexMatcherBuilder::new();
        bz.unicode(false);
        if word {
            bz.word(true);
        }
        if fixed {
            bz.fixed_strings(true);
        }
        if let Ok(m) = bz.build(pattern) {
            return Ok(m);
        }
    }
    if case_insensitive {
        let mut bi = RegexMatcherBuilder::new();
        bi.case_insensitive(true);
        if word {
            bi.word(true);
        }
        if fixed {
            bi.fixed_strings(true);
        }
        if let Ok(m) = bi.build(pattern) {
            return Ok(m);
        }
    }
    let mut bf = RegexMatcherBuilder::new();
    if word {
        bf.word(true);
    }
    if fixed {
        bf.fixed_strings(true);
    }
    bf.build(pattern)
}

/// Multi-pattern prefilter branches. Single non-fixed delegates to
/// `query_grams` exactly (default path identical). Fixed patterns are
/// literals: every 3-byte window is required (a literal matches only text
/// containing it whole), so short (<3 B) or empty patterns yield None
/// (full scan — an empty pattern matches every line). Multi-pattern ORs
/// every pattern's branches; any pattern without usable grams forces None,
/// since it can match files lacking the other patterns' grams.
fn query_grams_multi(patterns: &[String], fixed: bool) -> Option<Vec<Vec<u32>>> {
    if !fixed && patterns.len() == 1 {
        return query_grams(&patterns[0]);
    }
    let mut ors: Vec<Vec<u32>> = vec![];
    for p in patterns {
        if fixed {
            let bytes = p.as_bytes();
            if bytes.len() < 3 {
                return None;
            }
            let mut set = HashSet::new();
            for w in bytes.windows(3) {
                set.insert(gram_pack(&[w[0], w[1], w[2]]));
            }
            ors.push(set.into_iter().collect());
        } else {
            let mut branches = query_grams(p)?;
            ors.append(&mut branches);
        }
    }
    Some(ors)
}

/// Per-file cap (`-m`): keep the first m banked hits per file. Bank order is
/// file order, so this equals early exit with the same survivors; it runs
/// after verify (no sink change) and before rank/top/count/emit, matching
/// rg's capped `-c` shape. `None` (no `-m`) is a no-op.
fn apply_max_count(hits: &mut [FileHits], max_count: Option<usize>) {
    if let Some(m) = max_count {
        for fh in hits.iter_mut() {
            fh.metas.truncate(m);
        }
    }
}

/// Split `-f` bytes into patterns: one per `\n`, a single trailing `\r`
/// stripped per line, interior empty lines kept (rg 15.1.0: an empty `-f`
/// line matches every line — probed), the trailing-newline artifact
/// dropped, and a fully empty file yielding zero patterns (rg: `-f` with
/// no patterns matches nothing — probed).
fn split_pattern_lines(data: &[u8]) -> Vec<String> {
    if data.is_empty() {
        return vec![];
    }
    let text = String::from_utf8_lossy(data);
    let mut out: Vec<String> = text
        .split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l).to_string())
        .collect();
    if text.ends_with('\n') {
        out.pop();
    }
    out
}

/// Loud per-file build failure (exit 2, no index written): a corpus file the
/// build cannot read fails exactly like the scan side, never silently drops
/// from the index (a dropped file would return fewer indexed hits with exit
/// 0 where scan exits 2). Symlink-escape skips stay silent at the call site.
fn refuse_build_file(p: &std::path::Path, e: &dyn std::fmt::Display) -> ! {
    eprintln!("nkg: cannot read {}: {e}", p.display());
    std::process::exit(2);
}

/// Query-side phase timing, same opt-in gate and same stderr contract as the
/// `cmd_index` phases: unset in normal use, so stderr stays byte identical to
/// the un-instrumented build. One `var_os` per query. `emit` is the residual
/// from the end of `sort` to the diagnostics line (finalize + render + write),
/// because every arm shares that tail and there are four of them to time.
struct QueryPhases {
    on: bool,
    load: f64,
    walk: f64,
    rank: f64,
    verify: f64,
    sort: f64,
    tail: Instant,
    /// Hits handed to the socket. `emit` is a residual that includes socket
    /// backpressure, so the window alone cannot say whether emit is slow or
    /// the client is slow to read; per-row cost is what separates those.
    rows: u64,
}

/// Read once per process. The daemon answers many queries on one loop, and
/// re-reading the environment per query would put a lookup on the path the
/// probe is trying to measure.
static PHASE_TIMING: std::sync::LazyLock<bool> =
    std::sync::LazyLock::new(|| std::env::var_os("NKG_PHASE_TIMING").is_some());

impl QueryPhases {
    fn new() -> Self {
        QueryPhases {
            on: *PHASE_TIMING,
            load: 0.0,
            walk: 0.0,
            rank: 0.0,
            verify: 0.0,
            sort: 0.0,
            tail: Instant::now(),
            rows: 0,
        }
    }

    fn report(&self) {
        if self.on {
            // `tail` starts after `sort`, so its elapsed time IS the emit
            // window; the measured phases all closed before it.
            let emit = self.tail.elapsed().as_secs_f64() * 1e3;
            eprintln!(
                "nkg: phase: load {:.3} walk {:.3} rank {:.3} verify {:.3} sort {:.3} emit {:.3} rows {} (ms)",
                self.load,
                self.walk,
                self.rank,
                self.verify,
                self.sort,
                emit,
                self.rows
            );
        }
    }
}

fn cmd_index(root: &PathBuf, idx_path: &str) {
    let t0 = Instant::now();
    // Phase timing is opt-in: unset in normal use, so stderr stays byte
    // identical to the un-instrumented build.
    let timing = std::env::var_os("NKG_PHASE_TIMING").is_some();
    let ms = |t: &Instant| {
        if timing {
            t.elapsed().as_secs_f64() * 1e3
        } else {
            0.0
        }
    };
    let t_walk = Instant::now();
    let root_canon = canon_root(root);
    let (root_dev, root_ino) = root_cookie(&root_canon);
    let root_fp = root_canon.to_string_lossy().into_owned();
    let (paths, had_walk_error) = walk_files(root, &WalkOptions::default());
    let walk_ms = ms(&t_walk);
    let (canon_ns, read_ns, gram_ns) = (AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0));
    let file_bytes = AtomicU64::new(0);
    if had_walk_error {
        eprintln!("nkg: walk error: refusing to write a partial index to {idx_path}");
        std::process::exit(2);
    }
    // Self-exclusion: an index rebuilt inside its own corpus must not index
    // itself (scan never sees it as a match source either — JSON has no
    // planted text, but its bytes would still perturb the trigram table and
    // break indexed==scan). Canonicalize both sides; a not-yet-existing
    // output trivially matches nothing, so no absolutized fallback is needed.
    let idx_canon = std::fs::canonicalize(idx_path).ok();
    // Wall time for the whole parallel scan. The `canon`, `read` and `extract`
    // counters are CPU-ms summed across threads, so dividing them by the core
    // count estimates the section rather than measuring it — and that estimate
    // was wrong by 3x. Measured, this section runs at 11.3x on 32 cores, not
    // 32x, because it is memory-bandwidth-bound rather than scheduler-bound:
    // handing rayon larger chunks with `with_min_len` made it monotonically
    // worse, 41.6 ms at chunk 1 against 232.5 ms at chunk 512, so the default
    // splitting stands and the ceiling here is the hardware's.
    let t_scan = Instant::now();
    let entries: Vec<(String, GramSet)> = paths
        .par_iter()
        .filter_map(|p| {
            let tc = Instant::now();
            // Race-close: canonicalize FIRST, then read through the
            // canonical path with a no-follow open. The confinement check
            // and the bytes then share one resolution: a symlink swapped
            // in after the walk either resolves inside (read as-is) or
            // outside (prefix check drops it) or races the open itself
            // (O_NOFOLLOW refuses it) — never outside bytes stored under
            // an inside name. Unreadable files fail loudly (exit 2, no index
            // written) exactly like the scan side; only symlink-escape skips
            // silent — the same outcome as a walk-filtered file.
            let canon = match std::fs::canonicalize(p) {
                Ok(c) => c,
                Err(e) => refuse_build_file(p, &e),
            };
            if Some(&canon) == idx_canon.as_ref() {
                return None;
            }
            if timing {
                canon_ns.fetch_add(tc.elapsed().as_nanos() as u64, Ordering::Relaxed);
            }
            // Root-relative entry: canonicalize both sides so symlinked
            // roots (e.g. /tmp on macOS) fingerprint stably. Files escaping
            // the root via symlink are skipped, never stored absolute.
            let rel = canon
                .strip_prefix(&root_canon)
                .ok()?
                .to_string_lossy()
                .into_owned();
            let mut bytes = Vec::new();
            let tr = Instant::now();
            {
                use std::io::Read;
                let mut f = match open_verify_file(&canon, false) {
                    Ok(f) => f,
                    Err(e) => {
                        let raced_link = canon
                            .symlink_metadata()
                            .map(|m| m.file_type().is_symlink())
                            .unwrap_or(false);
                        if raced_link {
                            return None;
                        }
                        refuse_build_file(p, &e);
                    }
                };
                if let Err(e) = f.read_to_end(&mut bytes) {
                    refuse_build_file(p, &e);
                }
            }
            if timing {
                read_ns.fetch_add(tr.elapsed().as_nanos() as u64, Ordering::Relaxed);
                file_bytes.fetch_add(bytes.len() as u64, Ordering::Relaxed);
            }
            if is_binary(&bytes) {
                return None;
            }
            let tg = Instant::now();
            let grams = grams_of(&bytes);
            if timing {
                gram_ns.fetch_add(tg.elapsed().as_nanos() as u64, Ordering::Relaxed);
            }
            Some((rel, grams))
        })
        .collect();
    let scan_ms = ms(&t_scan);
    let t_pairs = Instant::now();
    let nfiles = entries.len();
    let mut files = Vec::with_capacity(nfiles);
    let mut pairs: Vec<(u32, u32)> = Vec::new();
    // Consume `entries` rather than borrow it. The gram sets are the largest
    // structure alive here -- one HashSet slot per incidence, the same count
    // `pairs` ends up holding at 8 bytes each -- so borrowing kept two ~41 MB
    // allocations live at once while `pairs` filled. Moving each set out lets
    // it drop as soon as its file is consumed, and moves the path instead of
    // cloning it.
    for (path, grams) in entries {
        let id = files.len() as u32;
        files.push(path);
        for g in &grams {
            pairs.push((*g, id));
        }
    }
    let pairs_ms = ms(&t_pairs);
    let incidences = pairs.len();
    let t_sort = Instant::now();
    // Sorting (gram, id) once yields the same per-key ascending id runs the
    // map form produced by pushing ids in file order.
    //
    // Packing each pair into one u64 (gram high, id low) and sorting that
    // instead was tried and reverted: it made the sort 30% slower, because
    // writing a 41 MB packed array costs more memory traffic than moving two
    // u32s inside a tuple saves. The tuple sort stands.
    pairs.par_sort_unstable();
    let sort_ms = ms(&t_sort);
    let t_asm = Instant::now();
    // One pass writes all three run vectors. Sizing them up front matters: the
    // previous form pushed into them and re-read `off.last_mut()` per element,
    // so every id cost a bounds check and a backwards load. Worth about 20%
    // of this phase.
    let n = pairs.len();
    let mut keys: Vec<u32> = Vec::with_capacity(n / 8 + 16);
    let mut off: Vec<u32> = Vec::with_capacity(n / 8 + 17);
    let mut ids: Vec<u32> = Vec::with_capacity(n);
    off.push(0);
    let mut prev_gram: u32 = 0;
    for (i, &(g, id)) in pairs.iter().enumerate() {
        if i == 0 || g != prev_gram {
            if i != 0 {
                // Close the run just finished. The first group must not push:
                // `off` starts at 0, and each later boundary plus one closing
                // entry makes exactly keys.len() + 1.
                off.push(ids.len() as u32);
            }
            keys.push(g);
            prev_gram = g;
        }
        ids.push(id);
    }
    off.push(ids.len() as u32);
    drop(pairs);
    let (nkeys, nids) = (keys.len(), ids.len());
    let asm_ms = ms(&t_asm);
    let t_enc = Instant::now();
    let postings = Postings::Owned { keys, off, ids };
    let idx = Index {
        root: root_fp,
        root_dev,
        root_ino,
        files,
        postings,
    };
    if idx_path.ends_with(".bin") {
        write_index_file(idx_path, &encode_index_bin(&idx));
    } else {
        let data = match serde_json::to_string(&idx) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("nkg: cannot encode index {idx_path}: {e}");
                std::process::exit(2);
            }
        };
        write_index_file(idx_path, data.as_bytes());
    }
    let enc_ms = ms(&t_enc);
    if timing {
        let out_bytes = std::fs::metadata(idx_path).map(|m| m.len()).unwrap_or(0);
        eprintln!(
            "nkg: phases walk={walk_ms:.1} scan={scan_ms:.1} canon={:.1} read={:.1} extract={:.1} pairs={pairs_ms:.1} sort={sort_ms:.1} assemble={asm_ms:.1} encode_write={enc_ms:.1} total={:.1} | files={} read_bytes={} incidences={} keys={} ids={} out_bytes={}",
            canon_ns.load(Ordering::Relaxed) as f64 / 1e6,
            read_ns.load(Ordering::Relaxed) as f64 / 1e6,
            gram_ns.load(Ordering::Relaxed) as f64 / 1e6,
            t0.elapsed().as_secs_f64() * 1e3,
            nfiles,
            file_bytes.load(Ordering::Relaxed),
            incidences,
            nkeys,
            nids,
            out_bytes,
        );
    }
    eprintln!(
        "nkg: indexed {} files in {} ms -> {idx_path}",
        nfiles,
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
#[cfg(unix)]
struct CachedFd {
    fd: std::os::unix::io::RawFd,
    len: u64,
    modified: std::time::SystemTime,
}

#[cfg(unix)]
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
    #[cfg(unix)]
    slots: Vec<std::sync::Mutex<Option<CachedFd>>>,
}

impl FdCache {
    fn new(nfiles: usize) -> Self {
        #[cfg(unix)]
        {
            let mut slots = Vec::with_capacity(nfiles);
            for _ in 0..nfiles {
                slots.push(std::sync::Mutex::new(None));
            }
            FdCache { slots }
        }
        #[cfg(not(unix))]
        {
            // No fd cache off unix: reads go through plain open+read.
            let _ = nfiles;
            FdCache {}
        }
    }
}

/// Best-effort NOFILE bump so the daemon can hold one fd per indexed file.
/// Never fails the daemon: when the ceiling stays low the cache just fills
/// what fits and fill-open errors fall back to plain open+read.
#[cfg(unix)]
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
            eprintln!("nkg: NOFILE cur={} max={}", after.rlim_cur, after.rlim_max);
        }
    }
}
/// Non-unix fallback: single-fd reads need no descriptor headroom.
#[cfg(not(unix))]
fn bump_nofile_for_cache(_want_files: usize) {}

/// pread loop into `buf` from offset 0 to EOF (offset-free: safe on a fd
/// shared across rayon workers). Appends like `read_to_end`.
#[cfg(unix)]
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
            libc::pread(fd, dst.as_mut_ptr() as *mut libc::c_void, dst.len(), off)
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

/// Open a corpus file for verify/index reads with walk-matching symlink
/// semantics: `follow == false` (the default; the walker runs unfollowed
/// unless `-L/--follow`) refuses symlinks atomically at open
/// (`O_NOFOLLOW`), so a symlink swapped in between walk and open is
/// skipped instead of followed outside the root. With `-L/--follow` the
/// open follows links exactly like the walker does. A refused symlink
/// surfaces as an IO error and the caller skips the file — the same
/// outcome as a walk-filtered file, byte-identical on success paths.
fn open_verify_file(path: &std::path::Path, follow: bool) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut o = std::fs::OpenOptions::new();
        o.read(true);
        if !follow {
            o.custom_flags(libc::O_NOFOLLOW);
        }
        o.open(path)
    }
    #[cfg(not(unix))]
    {
        // No O_NOFOLLOW off unix: best-effort no-follow check, still racy
        // there but no worse than before; the unix path is exact.
        if !follow
            && std::fs::symlink_metadata(path)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "refusing symlink without -L/--follow",
            ));
        }
        std::fs::File::open(path)
    }
}
fn plain_open_read(path: &str, buf: &mut Vec<u8>, follow: bool) -> std::io::Result<()> {
    use std::io::Read;
    open_verify_file(std::path::Path::new(path), follow)?.read_to_end(buf)?;
    Ok(())
}

/// Serve-side file read: warm-fd hit fstats the cached fd itself (no path
/// walk, no open/close) and preads it; miss or edit opens fresh, validates
/// the fd's own metadata, and caches it. `retried` bounds the EBADF re-read
/// after a concurrent replace closed the fd under us.
///
/// Freshness binds the fd, not the path: the served bytes come from the
/// cached fd, so its own fstat (len, mtime) — not a path stat taken
/// earlier — anchors the hit decision. A swap between the decision and
/// the pread then reads old-or-new atomically per fd, never
/// fresh-claimed stale bytes. The fd is additionally bound to the live
/// path by (dev, ino): a rename-swap leaves the old fd valid with
/// matching fstat, so identity must match too or the entry refreshes
/// from the live path (a pure-fstat check would serve pre-replace bytes
/// indefinitely). In-place edits change the fd's own fstat and miss the
/// same way. `follow` is false on the daemon path (the served index was
/// built unfollowed); the miss open still honors it. Any metadata/open
/// failure falls back to plain open+read, so the cache never fails where
/// the uncached path succeeds.
#[cfg(unix)]
fn read_verify_bytes(
    fdc: Option<(&FdCache, u32)>,
    path: &str,
    buf: &mut Vec<u8>,
    retried: bool,
    follow: bool,
) -> std::io::Result<()> {
    let (cache, id) = match fdc {
        None => return plain_open_read(path, buf, follow),
        Some(x) => x,
    };
    let slot = match cache.slots.get(id as usize) {
        Some(s) => s,
        None => return plain_open_read(path, buf, follow),
    };
    // Hit decision under one per-slot lock, no open/hash while holding
    // it. Poison-tolerant: a panicked holder must not wedge the daemon.
    // None (empty slot or any mismatch) falls to the fill path below.
    let hit_fd: Option<std::os::unix::io::RawFd> = 'hit: {
        let guard = slot.lock().unwrap_or_else(|e| e.into_inner());
        let e = match guard.as_ref() {
            Some(e) => e,
            None => break 'hit None,
        };
        // fstat the cached fd: the served bytes come from this fd, so its
        // own metadata decides freshness — never a path stat alone.
        let fm = {
            use std::os::unix::io::FromRawFd;
            // SAFETY: `e.fd` is a live cache-owned fd; the ManuallyDrop
            // File borrows it for one metadata call and never closes it.
            let borrowed = unsafe { std::mem::ManuallyDrop::new(std::fs::File::from_raw_fd(e.fd)) };
            match borrowed.metadata() {
                Ok(m) => m,
                Err(_) => break 'hit None,
            }
        };
        use std::os::unix::fs::MetadataExt;
        if fm.len() != e.len || fm.modified().ok() != Some(e.modified) {
            // The held fd itself changed under us (in-place edit): refill.
            break 'hit None;
        }
        let live = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return plain_open_read(path, buf, follow),
        };
        if live.dev() != fm.dev() || live.ino() != fm.ino() {
            // Rename-swap: the old fd is still valid but no longer the
            // live path — refill from the live path, never serve the
            // detached generation as current.
            break 'hit None;
        }
        match live.modified() {
            Ok(t) if live.len() == e.len && t == e.modified => Some(e.fd),
            Ok(_) => break 'hit None,
            Err(_) => return plain_open_read(path, buf, follow),
        }
    };
    if let Some(fd) = hit_fd {
        match pread_all(fd, buf) {
            Ok(()) => return Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::EBADF) && !retried => {
                // Lost the fd to a concurrent replace: drop the dead entry
                // and re-read once through the fresh path.
                *slot.lock().unwrap_or_else(|e| e.into_inner()) = None;
                return read_verify_bytes(fdc, path, buf, true, follow);
            }
            Err(e) => return Err(e),
        }
    }
    // Miss or edit: open + stat OUTSIDE the lock so one cold file never
    // stalls other workers' warm pread hits. The open honors `follow`
    // (no-follow by default), closing the swap-a-symlink-in window.
    let f = match open_verify_file(std::path::Path::new(path), follow) {
        Ok(f) => f,
        Err(_) => return plain_open_read(path, buf, follow),
    };
    let (flen, fmod) = match f
        .metadata()
        .and_then(|m| m.modified().map(|t| (m.len(), t)))
    {
        Ok(x) => x,
        Err(_) => return plain_open_read(path, buf, follow),
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
                *guard = Some(CachedFd {
                    fd: fresh,
                    len: flen,
                    modified: fmod,
                });
                fresh
            }
        }
    };
    match pread_all(fd, buf) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EBADF) && !retried => {
            *slot.lock().unwrap_or_else(|e| e.into_inner()) = None;
            read_verify_bytes(fdc, path, buf, true, follow)
        }
        Err(e) => Err(e),
    }
}
/// Non-unix fallback: no fd cache, plain open+read — same bytes as the
/// cold path.
#[cfg(not(unix))]
fn read_verify_bytes(
    _: Option<(&FdCache, u32)>,
    path: &str,
    buf: &mut Vec<u8>,
    _retried: bool,
    follow: bool,
) -> std::io::Result<()> {
    plain_open_read(path, buf, follow)
}

#[derive(Serialize, Deserialize)]
struct Query {
    pattern: String,
    top: Option<usize>,
    /// `-i` over serve: false on old clients (serde default), so old/new
    /// daemons interop — an old daemon just searches case-sensitively.
    #[serde(default)]
    ignore_case: bool,
    /// `-B`/`-C` over serve: 0 on old clients (serde default), so an old
    /// client gets plain hits from a new daemon and an old daemon (which
    /// ignores the unknown fields) serves plain hits to a new client.
    #[serde(default)]
    before: usize,
    /// `-A`/`-C` over serve: same interop contract as `before`.
    #[serde(default)]
    after: usize,
    /// MatchFlags over serve (all serde-defaulted: old clients omit them and
    /// get today's behavior from a new daemon; old daemons ignore them):
    /// `-w` word bounds, `-v` invert, `-m` per-file cap, the pattern list
    /// for grams/bonus (`patterns` empty = legacy single `pattern`), and
    /// whether that list is literal (`-F`).
    #[serde(default)]
    word: bool,
    #[serde(default)]
    invert: bool,
    #[serde(default)]
    max_count: Option<usize>,
    #[serde(default)]
    patterns: Vec<String>,
    #[serde(default)]
    fixed: bool,
    /// Subtree roots over serve (both serde-defaulted: old clients omit them
    /// and get whole-tree behavior from a new daemon; old daemons ignore
    /// them and serve whole-tree to a new client, which then over-returns —
    /// mixed-version skew, same as other new fields). `qroot` is the
    /// client-canonicalized absolute query root ("" = legacy whole tree);
    /// the daemon serves only files under it. `display_root` is the raw
    /// root operand for cold-shape display paths ("" = legacy rel paths).
    #[serde(default)]
    qroot: String,
    #[serde(default)]
    display_root: String,
}

/// Shared rank core (intersect/union/idf scoring, path bonus, depth penalty,
/// descending file-score order). The cold indexed path runs it; the
/// comparator and scoring are verbatim the old bodies.
/// Returns ordered candidate ids plus per-file scores with bonus/depth
/// folded (the cold early-exit proof reads `scores` by file id).
/// `qrel`/`display_root` re-base depth and bonus onto the cold-equivalent
/// path (`display_root.join(suffix)`, one `./` stripped); `None` scores
/// stored paths verbatim.
fn rank_ors(
    idx: &Index,
    ors: &[Vec<u32>],
    path_bonus: &dyn Fn(&str) -> bool,
) -> (Vec<u32>, Vec<f64>) {
    rank_ors_rooted(idx, ors, path_bonus, None, "")
}
fn daemon_rank_path<'a>(
    abs: &'a str,
    idx_root: &str,
    qrel: Option<&std::path::Path>,
    display_root: &str,
) -> std::borrow::Cow<'a, str> {
    // An empty `qrel` is a root, not the absence of one: it is what a
    // whole-tree query sends, because the client's canonicalized root equals
    // `idx.root` and `strip_prefix` of equal paths is `""`. Treating that
    // empty path as "no rebasing" scored the candidate on the daemon's
    // ABSOLUTE path, so `depth` counted however many components the machine's
    // directory layout happens to contribute and `path_bonus` matched against
    // that same absolute string -- the same query then reported a different
    // `score` over serve than cold, by exactly the leaked prefix length.
    // Only a legacy client that sent no `qroot` at all arrives as `None`, and
    // there the stored string is all there is to score.
    let qr = match qrel {
        Some(q) => q,
        None => return std::borrow::Cow::Borrowed(abs),
    };
    let rel = serve_display_path(abs, idx_root);
    let suffix = match std::path::Path::new(rel).strip_prefix(qr) {
        Ok(s) => s,
        Err(_) => return std::borrow::Cow::Borrowed(abs),
    };
    if display_root.is_empty() {
        return std::borrow::Cow::Owned(suffix.to_string_lossy().into_owned());
    }
    let joined = std::path::PathBuf::from(display_root)
        .join(suffix)
        .to_string_lossy()
        .into_owned();
    std::borrow::Cow::Owned(strip_dot_slash(&joined).to_owned())
}
/// `--stats`: print the query plan and candidate counts to stderr. The plan is
/// the only way to tell a good trigram choice from a bad one -- a branch whose
/// AND keeps 18k of 18k files is not being narrowed by the index, however fast
/// the search after it runs.
static STATS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn rank_ors_rooted(
    idx: &Index,
    ors: &[Vec<u32>],
    path_bonus: &dyn Fn(&str) -> bool,
    qrel: Option<&std::path::Path>,
    display_root: &str,
) -> (Vec<u32>, Vec<f64>) {
    let n = idx.files.len() as f64;
    // Decode only the postings this query actually names, into owned buffers
    // held for the whole loop. A raw index materializes none of its ~2.1M ids
    // at load, so this per-query decode is where those bytes become numbers.
    let mut runs: Vec<Vec<u32>> = Vec::new();
    let mut scratch: Vec<u32> = Vec::new();
    let slots: Vec<Vec<Option<usize>>> = ors
        .iter()
        .map(|ands| {
            ands.iter()
                .map(|g| match idx.postings.find(*g) {
                    None => None,
                    Some(i) => {
                        let run = idx.postings.ids_at(i, &mut scratch);
                        // No range check here, and none is needed: a run that
                        // is strictly ascending can only carry an out-of-range
                        // id as its maximum, which the load-time `last`
                        // check already refused; a run that is not strictly
                        // ascending is refused by `intersect_all` below,
                        // before any of these ids reaches `is_cand`. An
                        // earlier per-id check here was unreachable — a
                        // mid-run bad id desorts the run, so `intersect_all`
                        // exits first — and was deleted rather than shipped
                        // as an undemonstrable guard.
                        runs.push(run.to_vec());
                        Some(runs.len() - 1)
                    }
                })
                .collect()
        })
        .collect();
    // (postings, idf weight) per gram occurrence, in query order, for
    // deferred exact scoring of survivors only.
    let mut occ: Vec<(&[u32], f64)> = vec![];
    let mut cand: Vec<u32> = vec![];
    let mut tmp: Vec<u32> = vec![];
    // (trigram count, widest AND input, candidates) per OR branch, --stats only.
    let mut plan: Vec<(usize, usize, usize)> = vec![];
    for (ands, branch) in ors.iter().zip(slots.iter()) {
        let mut lists: Vec<&[u32]> = Vec::with_capacity(ands.len());
        let mut empty = false;
        for &slot in branch {
            match slot {
                None => {
                    empty = true;
                    break;
                }
                Some(j) => {
                    let list: &[u32] = &runs[j];
                    occ.push((list, (n / list.len() as f64).ln()));
                    lists.push(list);
                }
            }
        }
        if empty || lists.is_empty() {
            continue;
        }
        // Widest AND input bounds the result: intersecting n sorted lists can
        // only shrink the smallest one.
        let widest = lists.iter().map(|l| l.len()).max().unwrap_or(0);
        let branch = prefilter::intersect_all(&mut lists);
        if STATS.load(std::sync::atomic::Ordering::Relaxed) {
            plan.push((ands.len(), widest, branch.len()));
            let shown: Vec<String> = ands
                .iter()
                .map(|&g| {
                    String::from_utf8_lossy(&[
                        (g >> 16) as u8,
                        ((g >> 8) & 0xff) as u8,
                        (g & 0xff) as u8,
                    ])
                    .replace(['\n', '\r'], "?")
                })
                .collect();
            eprintln!("nkg:   grams [{}]", shown.join(" "));
        }
        prefilter::union_sorted_into(&cand, &branch, &mut tmp);
        std::mem::swap(&mut cand, &mut tmp);
    }
    if STATS.load(std::sync::atomic::Ordering::Relaxed) {
        eprintln!(
            "nkg: plan: {} OR branch(es), {} indexed file(s)",
            plan.len(),
            idx.files.len()
        );
        for (i, (grams, widest, hit)) in plan.iter().enumerate() {
            eprintln!(
                "nkg:   branch {i}: {grams} trigram(s), widest list {widest}, {hit} candidate file(s)"
            );
        }
        eprintln!("nkg:   union: {} candidate file(s) verified", cand.len());
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
    for &id in &cand {
        let p = &idx.files[id as usize];
        let rp = daemon_rank_path(p, &idx.root, qrel, display_root);
        let depth = std::path::Path::new(rp.as_ref()).components().count() as f64;
        let bonus = if path_bonus(rp.as_ref()) { 100.0 } else { 0.0 };
        scores[id as usize] += bonus - depth;
    }
    let mut order = cand;
    order.sort_by(|a, b| {
        scores[*b as usize]
            .partial_cmp(&scores[*a as usize])
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    (order, scores)
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

/// Decode an arena slice with the exact eager expression (`from_utf8_lossy`
/// then a char-trim of the line terminator only): valid UTF-8 borrows the
/// arena, only invalid-UTF8 hits allocate — the same hits as before. A CRLF
/// file keeps its `\r`: ripgrep's line content runs to the `\n` and still
/// carries the carriage return (probed byte-for-byte on rg 15.1.0), so
/// trimming it here diverged from the match set on every CRLF line.
fn banked_slice<'a>(arena: &'a [u8], start: u32, end: u32) -> std::borrow::Cow<'a, str> {
    let (s, e) = (start as usize, end as usize);
    let raw = arena.get(s..e).unwrap_or_else(|| {
        eprintln!("corrupt hit offsets ({s}..{e} of {})", arena.len());
        std::process::exit(2);
    });
    let cow = String::from_utf8_lossy(raw);
    match cow {
        std::borrow::Cow::Borrowed(b) => std::borrow::Cow::Borrowed(b.trim_end_matches('\n')),
        std::borrow::Cow::Owned(o) => std::borrow::Cow::Owned(o.trim_end_matches('\n').to_string()),
    }
}

/// Decode banked match bytes (unchanged contract: same expression as before,
/// now shared with context lines through `banked_slice`).
fn banked_text<'a>(fh: &'a FileHits, m: &HitMeta) -> std::borrow::Cow<'a, str> {
    banked_slice(&fh.arena, m.start, m.end)
}

/// Context attach (ContextLines): rebuild `fh` over the full file bytes.
/// The arena becomes one verbatim copy of `buf` (the match-banked bytes are
/// dropped — no duplicate storage), `line_starts` records the byte offset
/// of every 1-based line start (split on `\n`, mirroring the searcher), and
/// each meta is remapped to its line's byte range, so `banked_text` decodes
/// byte-identical text. Call only when context>0 with surviving hits.
fn attach_context(fh: &mut FileHits, buf: &[u8]) {
    let mut starts: Vec<u32> = vec![0];
    for (i, &b) in buf.iter().enumerate() {
        if b == b'\n' && i + 1 < buf.len() {
            starts.push((i + 1) as u32);
        }
    }
    for m in fh.metas.iter_mut() {
        if m.line == 0 {
            eprintln!("corrupt hit line 0");
            std::process::exit(2);
        }
        let k = m.line as usize - 1;
        let s = *starts.get(k).unwrap_or_else(|| {
            eprintln!("corrupt hit line {} of {} lines", m.line, starts.len());
            std::process::exit(2);
        }) as usize;
        let e = if k + 1 < starts.len() {
            starts[k + 1] as usize
        } else {
            buf.len()
        };
        m.start = s as u32;
        m.end = e as u32;
    }
    fh.arena = buf.to_vec();
    fh.line_starts = starts;
}

/// Context windows over sorted unique 1-based match lines: `[line-before,
/// line+after]` clamped low at 1 (file top), merged when overlapping or
/// adjacent (rg merges `[2,4]+[5,7]` with no separator — probed on 15.1.0).
/// The high end stays unclamped: callers skip lines past EOF, and the merge
/// outcome is identical with or without the clamp (a clamp can only split
/// below a later window's start, which implies the unclamped span splits
/// there too).
fn compute_groups(lines: &[u64], before: usize, after: usize) -> Vec<(u64, u64)> {
    let mut groups: Vec<(u64, u64)> = vec![];
    for &l in lines {
        let lo = l.saturating_sub(before as u64).max(1);
        let hi = l.saturating_add(after as u64).max(1);
        match groups.last_mut() {
            Some(g) if lo <= g.1.saturating_add(1) => {
                if hi > g.1 {
                    g.1 = hi;
                }
            }
            _ => groups.push((lo, hi)),
        }
    }
    groups
}

/// Context line text over an attached file: the `line_no`-th line decoded
/// with the same expression as `banked_text`.
fn ctx_line_text<'a>(fh: &'a FileHits, line_no: u64) -> std::borrow::Cow<'a, str> {
    if line_no == 0 {
        eprintln!("corrupt context line 0");
        std::process::exit(2);
    }
    let k = line_no as usize - 1;
    let s = *fh.line_starts.get(k).unwrap_or_else(|| {
        eprintln!(
            "corrupt context line {line_no} of {} lines",
            fh.line_starts.len()
        );
        std::process::exit(2);
    });
    let e = if k + 1 < fh.line_starts.len() {
        fh.line_starts[k + 1]
    } else {
        fh.arena.len() as u32
    };
    banked_slice(&fh.arena, s, e)
}

/// Rank-ordered file groups for context render: the ranked flat order `ord`
/// folded into per-file surviving-meta lists in first-seen (rank) order,
/// metas ascending by line within a file. Rank by hit, context attached:
/// `--top` truncates `ord` first, so groups only ever cover survivors.
/// Shared by the cold and serve renderers so both print the same groups in
/// the same order from the same hit set.
fn ctx_file_groups(
    files: &[FileHits],
    loc: &[(u32, u32)],
    ord: &[u32],
) -> Vec<(usize, Vec<usize>)> {
    let mut by_file: Vec<Vec<usize>> = vec![Vec::new(); files.len()];
    let mut seen: Vec<bool> = vec![false; files.len()];
    let mut order: Vec<usize> = vec![];
    for &i in ord {
        let (fi, mi) = loc[i as usize];
        let fi = fi as usize;
        if !seen[fi] {
            seen[fi] = true;
            order.push(fi);
        }
        by_file[fi].push(mi as usize);
    }
    let mut out = Vec::with_capacity(order.len());
    for fi in order {
        let mis = &mut by_file[fi];
        mis.sort_by_key(|&mi| files[fi].metas[mi].line);
        out.push((fi, std::mem::take(mis)));
    }
    out
}

/// Sorted unique match lines for one group file: the merge input for
/// `compute_groups` (deduped — a line with several hits renders once, like
/// rg — while hit *counts* still come from `ord`, multiplicity intact).
fn ctx_group_lines(files: &[FileHits], fi: usize, mis: &[usize]) -> Vec<u64> {
    let mut v: Vec<u64> = mis.iter().map(|&mi| files[fi].metas[mi].line).collect();
    v.sort();
    v.dedup();
    v
}

/// Best score any hit in a file can reach. `ColCollector::matched` computes
/// `file_score - line/1e6` with `line >= 1`, so this is that exact expression
/// at line 1 — same arithmetic, so callers compare against a bound that is
/// exact rather than a rounded `kth + 1e-6`.
///
/// The exit test needs this rather than `file_score` itself: a match always
/// scores strictly below its own file, so a `file_score <= kth` form could
/// never hold and top-k verified every candidate. A hit that ties `kth`
/// exactly cannot displace it either — banked hits are appended in rank order
/// and `raw_order` is a stable sort, so an unverified hit at `kth` sorts
/// after every banked hit at `kth` and `truncate` drops it, exactly as a full
/// verify would.
fn best_hit_score(file_score: f64) -> f64 {
    file_score - 1.0 / 1e6
}

/// Batched parallel verify in descending file-score order with provable top-k
/// early exit (spec §6). `order` is candidate ids in descending file score and
/// `scores` is indexed by file id. `verify` is the per-file step, so the cold
/// path and the serve-cached path run one copy of the proof instead of two
/// that can drift apart. Every match scores at most
/// `best_hit_score(file_score)`, so once k hits are banked no unverified file
/// that cannot beat the kth-best hit can displace the top-k.
///
/// Full queries never early-exit (k = MAX), so the sequential batch waves
/// would be pure barrier overhead: those verify every candidate in one wave.
fn verify_batched<F>(
    order: &[u32],
    scores: &[f64],
    top: Option<usize>,
    log_exit: bool,
    verify: F,
) -> Vec<FileHits>
where
    F: Fn(u32) -> Option<FileHits> + Sync,
{
    if top == Some(0) {
        return vec![];
    }
    const BATCH: usize = 64;
    if top.is_none() {
        return order.par_iter().filter_map(|id| verify(*id)).collect();
    }
    let k = top.unwrap_or(usize::MAX);
    let mut all: Vec<FileHits> = vec![];
    let mut total = 0usize;
    let mut kth = f64::NEG_INFINITY;
    let mut done = 0usize;
    for chunk in order.chunks(BATCH) {
        if total >= k && best_hit_score(scores[chunk[0] as usize]) <= kth {
            // Cold only: the daemon is a long-running process, and one line
            // per top-k request is unbounded log growth there.
            if log_exit {
                eprintln!("nkg: early exit after {done} of {} files", order.len());
            }
            break;
        }
        // Per-file exit at file granularity (spec §6, same proof as the batch
        // check): a file whose best achievable hit does not beat kth
        // contributes no top-k hit. Same `best_hit_score` bound as the batch
        // exit, applied per file, so the surviving set — ties included —
        // matches the batch-only path.
        let armed = total >= k;
        let kth_now = kth;
        let mut batch: Vec<FileHits> = chunk
            .par_iter()
            .filter(|id| !armed || best_hit_score(scores[**id as usize]) > kth_now)
            .filter_map(|id| verify(*id))
            .collect();
        total += batch.iter().map(|f| f.metas.len()).sum::<usize>();
        all.append(&mut batch);
        done += chunk.len();
        if total >= k {
            // Only the k-th largest is read, so partition at k-1 instead of
            // sorting every banked meta: O(M) per chunk, not O(M log M). The
            // `loc` half of `flat_scores` is never built here either.
            let n: usize = all.iter().map(|f| f.metas.len()).sum();
            let mut s: Vec<f64> = Vec::with_capacity(n);
            for f in &all {
                s.extend(f.metas.iter().map(|m| m.score));
            }
            s.select_nth_unstable_by(k - 1, |a, b| {
                b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal)
            });
            kth = s[k - 1];
        }
    }
    all
}

/// Daemon hardening bounds (localhost trust; wire token parked — see
/// `load_serve_port`). `MAX_SERVE_LINE_BYTES` caps one wire line;
/// `MAX_SERVE_CONNECTIONS` caps concurrent handler threads. Over-limit →
/// drop this connection; the daemon survives.
const MAX_SERVE_LINE_BYTES: u64 = 1 << 20;
const MAX_SERVE_CONNECTIONS: usize = 64;

/// Bytes one response batch accumulates before it goes to the socket. Every
/// emit appends exactly one newline-terminated row, so a batch boundary
/// always lands on a row boundary and the client's `read_line` framing is
/// untouched. Matches the socket `BufWriter` capacity, so shipping batches
/// makes no syscall the single buffered write did not already make.
const SERVE_EMIT_BYTES: usize = 64 * 1024;

/// One row out; the batch out once it fills. `emit` appends exactly one
/// newline-terminated row — that is the whole framing contract, and the
/// reason a mid-row flush cannot happen here. A failed socket write is
/// latched, never retried: the caller stops emitting on it, exactly as the
/// single whole-response write stopped the connection.
fn serve_emit_line(
    writer: &mut impl Write,
    buf: &mut Vec<u8>,
    broken: &mut bool,
    emit: impl FnOnce(&mut Vec<u8>),
) {
    emit(buf);
    if buf.len() >= SERVE_EMIT_BYTES {
        if writer.write_all(buf).is_err() {
            *broken = true;
        }
        buf.clear();
    }
}
fn handle_client(stream: TcpStream, idx: Arc<Index>, fdc: Arc<FdCache>) {
    // Per-query liveness: hung clients must not pin a slot forever.
    let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(60)));
    let reader_src = match stream.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut reader = BufReader::new(reader_src);
    let mut writer = std::io::BufWriter::with_capacity(64 * 1024, stream);
    let mut line = String::new();
    loop {
        line.clear();
        // Bounded line: `take` caps bytes copied into `line` so a gigabyte
        // line allocates at most MAX+1, then this connection drops.
        let n = match (&mut reader)
            .take(MAX_SERVE_LINE_BYTES + 1)
            .read_line(&mut line)
        {
            Err(e) => {
                eprintln!("nkg: serve read: {e}");
                break;
            }
            Ok(n) => n,
        };
        if n == 0 {
            break;
        }
        if n as u64 > MAX_SERVE_LINE_BYTES || !line.ends_with('\n') {
            break;
        }
        let t0 = Instant::now();
        // Same opt-in gate and same stderr contract as the one-shot path.
        // The daemon holds the index, so `load` and `walk` are structurally
        // zero here and are reported as such rather than omitted.
        let mut ph = QueryPhases::new();
        // Columnar serve emission: borrow-banked FileHits through the fd
        // cache, rank once over the side scores vec, escape each unique
        // path once, emit via emit_raw_with_path, single socket write.
        // Byte-identical wire (one object per line plus the done line);
        // no per-hit serde struct setup, no Arc path clones, no per-hit
        // path escaping.
        let mut broken = false;
        let mut ctx_asked = false;
        // Request-scoped I/O-error latch: concurrent clients must never
        // cross-attribute (one client's drain cannot steal another's flag).
        let latch = AtomicBool::new(false);
        let mut verify_err = false;
        match serde_json::from_str::<Query>(line.trim()) {
            Err(_) => {}
            Ok(q) => {
                ctx_asked = q.before > 0 || q.after > 0;
                // MatchFlags serve half: legacy clients send only `pattern`
                // (`patterns` empty); new clients send the pattern list plus
                // flags, and the combined alternation rebuilds server-side so
                // serve==cold on every flag mix.
                let q_pats: Vec<String> = if q.patterns.is_empty() {
                    vec![q.pattern.clone()]
                } else {
                    q.patterns.clone()
                };
                let q_combined = combine_patterns(&q_pats, q.fixed);
                let q_fixed_single = q.fixed && q_pats.len() == 1;
                match build_matcher_opts(&q_combined, q.ignore_case, q.word, q_fixed_single) {
                    Err(e) => {
                        if writeln!(writer, "{{\"error\":\"{e}\"}}").is_err() {
                            broken = true;
                        }
                    }
                    Ok(matcher) => {
                        // Subtree queries (--port with a path operand): the
                        // client sends its canonicalized absolute root plus
                        // the raw operand for display. Relativize against the
                        // index root; outside-index roots serve zero hits.
                        let qrel: Option<std::path::PathBuf> = if q.qroot.is_empty() {
                            None
                        } else {
                            std::path::Path::new(&q.qroot)
                                .strip_prefix(&idx.root)
                                .ok()
                                .map(|r| r.to_owned())
                        };
                        let q_outside = !q.qroot.is_empty() && qrel.is_none();
                        // `-i` skips trigram pruning: the postings are raw bytes,
                        // so case-sensitive grams would false-negative
                        // (`hello` grams miss `HELLO` files). Full-file verify
                        // keeps serve==cold on every `-i` query. `-v` skips it
                        // too: inverted matches live outside the gram files, so
                        // pruning would false-negative by construction.
                        let all_files =
                            || (0..idx.files.len() as u32).map(|id| (id, 0.0)).collect();
                        let t_rank = Instant::now();
                        let order: Vec<(u32, f64)> = if q.ignore_case || q.invert {
                            all_files()
                        } else if q.patterns.is_empty() && !q.fixed {
                            match query_grams(&q.pattern) {
                                None => all_files(),
                                Some(ors) => {
                                    let (o, s) = rank_ors_rooted(
                                        &idx,
                                        &ors,
                                        &|p| p.contains(q.pattern.as_str()),
                                        qrel.as_deref(),
                                        &q.display_root,
                                    );
                                    o.into_iter().map(|id| (id, s[id as usize])).collect()
                                }
                            }
                        } else {
                            match query_grams_multi(&q_pats, q.fixed) {
                                None => all_files(),
                                Some(ors) => {
                                    let (o, s) = rank_ors_rooted(
                                        &idx,
                                        &ors,
                                        &|p| q_pats.iter().any(|pat| p.contains(pat.as_str())),
                                        qrel.as_deref(),
                                        &q.display_root,
                                    );
                                    o.into_iter().map(|id| (id, s[id as usize])).collect()
                                }
                            }
                        };
                        ph.rank = t_rank.elapsed().as_secs_f64() * 1e3;
                        // Narrow candidates to the subtree (whole tree when
                        // qroot is legacy-empty; zero files when outside).
                        let order: Vec<(u32, f64)> = if q_outside {
                            vec![]
                        } else if let Some(qr) = &qrel {
                            if qr.as_os_str().is_empty() {
                                order
                            } else {
                                order
                                    .into_iter()
                                    .filter(|(id, _)| {
                                        std::path::Path::new(serve_display_path(
                                            &idx.files[*id as usize],
                                            &idx.root,
                                        ))
                                        .strip_prefix(qr)
                                        .is_ok()
                                    })
                                    .collect()
                            }
                        } else {
                            order
                        };
                        // Serve shares the cold top-k early exit: `order` is
                        // already descending by file score, and the warm fd
                        // cache only changes how a file is read, not what it
                        // may score. Splitting into ids plus an id-indexed
                        // score table is the shape `verify_batched` takes.
                        let mut dscores: Vec<f64> = vec![0.0; idx.files.len()];
                        let ids: Vec<u32> = order
                            .iter()
                            .map(|(id, s)| {
                                dscores[*id as usize] = *s;
                                *id
                            })
                            .collect();
                        let t_verify = Instant::now();
                        let mut files: Vec<FileHits> =
                            verify_batched(&ids, &dscores, q.top, false, |id| {
                                // Frozen-wrapper fast path (agreed with
                                // ContextLines): plain non-inverted queries run
                                // the frozen entry (exactly _ctx(0,0,false));
                                // context/invert go direct. Zero behavior change.
                                if q.before == 0 && q.after == 0 && !q.invert {
                                    verify_one_raw_cached(
                                        &latch,
                                        id,
                                        &idx.files[id as usize],
                                        &matcher,
                                        dscores[id as usize],
                                        Some((&*fdc, id)),
                                        false,
                                    )
                                } else {
                                    verify_one_raw_cached_ctx(CachedVerify {
                                        err: &latch,
                                        pid: id,
                                        path: &idx.files[id as usize],
                                        matcher: &matcher,
                                        file_score: dscores[id as usize],
                                        before: q.before,
                                        after: q.after,
                                        fdc: Some((&*fdc, id)),
                                        invert: q.invert,
                                        follow: false,
                                    })
                                }
                            });
                        ph.verify = t_verify.elapsed().as_secs_f64() * 1e3;
                        // `-m` caps each file before rank/top, mirroring the cold
                        // path (capped `-c` shapes come out of the wire for free).
                        let t_sort = Instant::now();
                        apply_max_count(&mut files, q.max_count);
                        verify_err |= take_verify_io_error(&latch);
                        let (hit_scores, loc) = flat_scores(&files);
                        let mut ord = raw_order(&hit_scores);
                        if let Some(n) = q.top {
                            ord.truncate(n);
                        }
                        ph.sort = t_sort.elapsed().as_secs_f64() * 1e3;
                        // `tail` runs from here to the flush, so its elapsed
                        // time IS the emit window: path escaping, rendering
                        // and the socket write.
                        // `ord` is exactly the hit set about to be rendered, so
                        // this is the exact row count with no per-row work.
                        ph.rows = ord.len() as u64;
                        ph.tail = Instant::now();
                        let mut esc: Vec<Option<Vec<u8>>> = vec![None; idx.files.len()];
                        for &i in &ord {
                            let (fi, _) = loc[i as usize];
                            let pid = files[fi as usize].pid as usize;
                            if esc[pid].is_none() {
                                // Display matches cold: legacy whole-tree
                                // queries emit index-root-relative paths;
                                // subtree queries re-root under the raw
                                // operand (absolute stays absolute, relative
                                // stays relative), mirroring walk output.
                                let rel = serve_display_path(&idx.files[pid], &idx.root);
                                let disp: std::borrow::Cow<str> = if q.display_root.is_empty() {
                                    std::borrow::Cow::Borrowed(rel)
                                } else if let Some(qr) = &qrel {
                                    match std::path::Path::new(rel).strip_prefix(qr) {
                                        Ok(sub) => match sub.as_os_str().is_empty() {
                                            true => std::borrow::Cow::Borrowed(strip_dot_slash(
                                                &q.display_root,
                                            )),
                                            false => std::borrow::Cow::Owned(
                                                strip_dot_slash(
                                                    &std::path::PathBuf::from(&q.display_root)
                                                        .join(sub)
                                                        .to_string_lossy(),
                                                )
                                                .to_owned(),
                                            ),
                                        },
                                        Err(_) => std::borrow::Cow::Borrowed(rel),
                                    }
                                } else {
                                    std::borrow::Cow::Borrowed(rel)
                                };
                                let mut v = Vec::with_capacity(disp.len() + 2);
                                push_escaped_json(&mut v, &disp);
                                esc[pid] = Some(v);
                            }
                        }
                        let ctx_on = q.before > 0 || q.after > 0;
                        // Bounded batch scratch, not the whole response: rows
                        // ship as they render, so the daemon never holds a
                        // full-response buffer (7.6 MB on a 51k-row query).
                        let mut buf: Vec<u8> = Vec::with_capacity(SERVE_EMIT_BYTES);
                        if ctx_on {
                            // Rank by hit, context attached: the ranked `ord` is
                            // folded into per-file groups (first-seen = rank
                            // order, `--top` already applied), windows expanded
                            // and merged, then hits ride as hit JSON with carried
                            // context lines (`"ctx":true`, file score) in span
                            // order. Same groups the cold renderer prints.
                            let mut fscore = vec![0.0f64; idx.files.len()];
                            for (id, s) in &order {
                                fscore[*id as usize] = *s;
                            }
                            for (fi, mis) in ctx_file_groups(&files, &loc, &ord) {
                                // A socket that stopped reading must not be
                                // written again: the per-write timeout has
                                // already spent 60 s once.
                                if broken {
                                    break;
                                }
                                let fh = &files[fi];
                                let pe = esc[fh.pid as usize].as_ref().unwrap();
                                let nlines = fh.line_starts.len() as u64;
                                let mlines = ctx_group_lines(&files, fi, &mis);
                                let mut k = 0usize;
                                for (lo, hi) in compute_groups(&mlines, q.before, q.after) {
                                    // No separator travels the wire: the client
                                    // owns `--group-separator` and recomputes the
                                    // same groups from the hit lines.
                                    let hi = hi.min(nlines);
                                    let mut ln = lo;
                                    while ln <= hi {
                                        if k < mis.len() && fh.metas[mis[k]].line == ln {
                                            while k < mis.len() && fh.metas[mis[k]].line == ln {
                                                let m = &fh.metas[mis[k]];
                                                let text = banked_text(fh, m);
                                                serve_emit_line(
                                                    &mut writer,
                                                    &mut buf,
                                                    &mut broken,
                                                    |b| {
                                                        emit_raw_with_path(
                                                            b, pe, m.line, &text, m.score,
                                                        )
                                                    },
                                                );
                                                k += 1;
                                            }
                                        } else {
                                            let text = ctx_line_text(fh, ln);
                                            serve_emit_line(
                                                &mut writer,
                                                &mut buf,
                                                &mut broken,
                                                |b| {
                                                    emit_ctx_json(
                                                        b,
                                                        pe,
                                                        ln,
                                                        &text,
                                                        fscore[fh.pid as usize],
                                                    )
                                                },
                                            );
                                        }
                                        ln += 1;
                                    }
                                }
                            }
                        } else {
                            for &i in &ord {
                                if broken {
                                    break;
                                }
                                let (fi, mi) = loc[i as usize];
                                let fh = &files[fi as usize];
                                let m = &fh.metas[mi as usize];
                                let text = banked_text(fh, m);
                                serve_emit_line(&mut writer, &mut buf, &mut broken, |b| {
                                    emit_raw_with_path(
                                        b,
                                        esc[fh.pid as usize].as_ref().unwrap(),
                                        m.line,
                                        &text,
                                        m.score,
                                    )
                                });
                            }
                        }
                        // Tail batch: the rows that did not fill one. Still a
                        // plain `write_all`, and `done` still goes last below.
                        if writer.write_all(&buf).is_err() {
                            broken = true;
                        }
                    }
                }
            }
        }
        // Sub-millisecond precision: a served query is a few ms of work, and
        // integer millis report every hot query as 0. Float ms keeps the
        // field meaningful for the one mode where it is the only timing the
        // caller gets (the daemon holds the index, so the client cannot
        // subtract startup the way it can for a one-shot run).
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        let done = if ctx_asked && verify_err {
            format!("{{\"done\":true,\"ms\":{ms:.3},\"ctx\":true,\"verify_error\":true}}")
        } else if ctx_asked {
            format!("{{\"done\":true,\"ms\":{ms:.3},\"ctx\":true}}")
        } else if verify_err {
            format!("{{\"done\":true,\"ms\":{ms:.3},\"verify_error\":true}}")
        } else {
            format!("{{\"done\":true,\"ms\":{ms:.3}}}")
        };
        if writeln!(writer, "{done}").is_err() {
            broken = true;
        }
        if writer.flush().is_err() {
            broken = true;
        }
        ph.report();
        if broken {
            break;
        }
        line.clear();
    }
}

fn serve_info_path(idx_path: &str) -> String {
    format!("{idx_path}.serve.json")
}

/// Linux `/proc/<pid>/stat` starttime (field 22), or None when unavailable
/// (non-Linux, vanished pid, parse failure). Cheap pid-reuse guard.
#[cfg(target_os = "linux")]
fn proc_starttime(pid: u32) -> Option<u64> {
    let data = std::fs::read(format!("/proc/{pid}/stat")).ok()?;
    let text = String::from_utf8_lossy(&data);
    let after = text.rfind(')')?;
    let fields: Vec<&str> = text[after + 1..].split_whitespace().collect();
    // After `(comm)`: state(3)..starttime(22) → index 19.
    fields.get(19)?.parse::<u64>().ok()
}
#[cfg(not(target_os = "linux"))]
fn proc_starttime(_pid: u32) -> Option<u64> {
    None
}
/// True when `pid` plausibly exists. Unix: `kill(pid, 0)`; EPERM means the
/// process exists but we may not signal it. Unknown platforms: assume alive
/// (the connect probe still fails closed to the cold path).
fn pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(unix)]
    {
        // SAFETY: kill with sig 0 sends nothing; return/errno only.
        let r = unsafe { libc::kill(pid as i32, 0) };
        if r == 0 {
            return true;
        }
        let e = std::io::Error::last_os_error().raw_os_error();
        // EPERM (1) = alive, no permission; ESRCH (3) = no such process.
        e == Some(libc::EPERM)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}
#[derive(Serialize, Deserialize)]
struct ServerInfo {
    pid: u32,
    port: u16,
    /// Daemon starttime for pid-reuse detection; 0 = unknown (old files,
    /// non-Linux). Serde-defaulted so old sidecars still parse.
    #[serde(default)]
    starttime: u64,
}

fn save_serve_info(idx_path: &str, port: u16) {
    let pid = std::process::id();
    let info = ServerInfo {
        pid,
        port,
        starttime: proc_starttime(pid).unwrap_or(0),
    };
    let Ok(s) = serde_json::to_string(&info) else {
        return;
    };
    let path = serve_info_path(idx_path);
    // No-symlink write: refuse to truncate a planted link target.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        opts.custom_flags(libc::O_NOFOLLOW);
        match opts.open(&path) {
            Ok(mut f) => {
                use std::io::Write as _;
                let _ = f.write_all(s.as_bytes());
                let _ = f.write_all(b"\n");
            }
            Err(e) => {
                eprintln!("nkg: refuse serve sidecar {path}: {e}");
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = std::fs::write(path, s + "\n");
    }
}

/// Serve-first probe outcome: a hit, a silent cold fallback (no sidecar ever
/// registered or an unparseable sidecar — fresh-user stderr stays clean), or
/// a single warned fallback (stale pid/reuse, or a live registration whose
/// listener/reply failed). At most one line is ever printed by the caller.
enum ServeProbe {
    Hit(ServeRows),
    MissSilent,
    MissWarn(String),
}

/// One served wire row, borrowed out of the line it was scanned from.
/// `text` is still JSON-escaped: `push_unescaped_json` decodes it.
struct WireRow<'a> {
    path: &'a [u8],
    line: u64,
    text: &'a [u8],
}

/// Split one served row by field position, the way `served_wire_paths`
/// reads `path`: `emit_raw_with_path` / `emit_ctx_json` both open
/// `{"path":"`, so a `{"path":"` inside the match TEXT sits past every field
/// this scan stops at and cannot be reached, whatever the text contains.
/// `path` and `text` terminate on their own `"`, and their `"` / `\` arrive
/// escaped (`\"`, `\\`), so stepping two bytes past a backslash lands exactly
/// on the terminator instead of stopping inside the field. `None` on a
/// truncated, non-wire or trailing-garbage line, so an unparseable line is
/// skipped rather than panicking.
fn scan_wire_row(line: &[u8]) -> Option<WireRow<'_>> {
    /// End of a JSON string body: first unescaped `"`, else None. memchr2
    /// skips the quote/backslash-free run the way `push_escaped_json` skips
    /// it on the emit side, which is every byte of every corpus row.
    fn end_of_str(s: &[u8]) -> Option<usize> {
        let mut i = 0;
        while i <= s.len() {
            let k = i + memchr::memchr2(b'"', b'\\', &s[i..])?;
            if s[k] == b'"' {
                return Some(k);
            }
            i = k + 2; // step over the escaped byte
        }
        None
    }
    let mut rest = line.strip_prefix(br#"{"path":""#)?;
    let end = end_of_str(rest)?;
    let path = &rest[..end];
    rest = rest[end + 1..].strip_prefix(br#","line":"#)?;
    let digits = memchr::memchr(b',', rest)?;
    let line_no = std::str::from_utf8(&rest[..digits]).ok()?.parse().ok()?;
    rest = rest[digits..].strip_prefix(br#","text":""#)?;
    let end = end_of_str(rest)?;
    // A complete row ends `,"score":N}` with nothing after the brace.
    let tail = &rest[end + 1..];
    if !(tail.ends_with(b"}") && !tail.ends_with(br#","ctx":true}"#)) {
        return None;
    }
    Some(WireRow {
        path,
        line: line_no,
        text: &rest[..end],
    })
}

/// Decode a JSON string body (no surrounding quotes) into `dst` — the
/// inverse of `push_escaped_json`, so a row decoded here is byte-identical
/// to the `&str` that went on the wire. An unknown or truncated escape
/// degrades to its literal bytes instead of panicking.
fn push_unescaped_json(dst: &mut Vec<u8>, s: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    fn hex(b: u8) -> Option<u8> {
        HEX.iter().position(|&h| h == b).map(|p| p as u8)
    }
    let mut start = 0usize;
    let mut i = 0usize;
    // memchr skips the escape-free run, which is every byte of every corpus
    // row; the byte loop below only runs on the rare rows that carry one.
    while let Some(rel) = memchr::memchr(b'\\', &s[i..]) {
        let k = i + rel;
        dst.extend_from_slice(&s[start..k]);
        i = k + 1;
        match s.get(i) {
            Some(b'n') => dst.push(b'\n'),
            Some(b'r') => dst.push(b'\r'),
            Some(b't') => dst.push(b'\t'),
            Some(b'b') => dst.push(0x08),
            Some(b'f') => dst.push(0x0C),
            Some(c @ (b'"' | b'\\')) => dst.push(*c),
            // `\u00XX` is the only \u form push_escaped_json emits, so the
            // four hex digits are one code point — always a control, hence
            // one byte. Anything wider still decodes as UTF-8, which is what
            // serde_json would have produced for it.
            Some(b'u') => {
                let d = |k: usize| s.get(i + k).and_then(|&b| hex(b));
                match (d(1), d(2), d(3), d(4)) {
                    (Some(a), Some(b), Some(c), Some(e)) => {
                        let cp = u32::from(a) << 12
                            | u32::from(b) << 8
                            | u32::from(c) << 4
                            | u32::from(e);
                        match char::from_u32(cp) {
                            Some(ch) => {
                                dst.extend_from_slice(ch.encode_utf8(&mut [0u8; 4]).as_bytes())
                            }
                            None => dst.push(b'u'),
                        }
                        i += 4;
                    }
                    _ => dst.push(b'u'),
                }
            }
            // Unknown or truncated escape: the backslash stands, so a
            // malformed row degrades instead of panicking.
            _ => {}
        }
        i = (i + 1).min(s.len());
        start = i;
    }
    dst.extend_from_slice(&s[start..]);
}
/// Quiet sidecar read: `Ok(None)` = absent/corrupt (silent fallback),
/// `Err(msg)` = stale pid/reuse (caller prints `msg` once, no second
/// `server unreachable` line), `Ok(Some(port))` = live registration.
///
/// Trust model (accepted): localhost-only bind, no wire token. The query
/// pattern travels to 127.0.0.1:port in cleartext and any local listener on
/// the recorded port can answer; that disclosure is documented localhost
/// trust, not a boundary. A shared-secret wire token was considered and
/// parked (sidecar-secret rotation/forwarding complexity outweighs the gain
/// while any local user can already bind loopback). The pid-liveness +
/// starttime check here closes only the stale-file / port-reuse hijack: a
/// dead daemon's sidecar never diverts a query.
fn load_serve_port_quiet(idx_path: &str) -> Result<Option<u16>, String> {
    let path = serve_info_path(idx_path);
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(_) => return Ok(None),
    };
    let info: ServerInfo = match serde_json::from_str(data.trim()) {
        Ok(i) => i,
        Err(_) => return Ok(None),
    };
    if info.port == 0 || !pid_alive(info.pid) {
        return Err(format!(
            "nkg: stale serve file {path} (pid {} not running); falling back to cold index load",
            info.pid
        ));
    }
    if info.starttime != 0 {
        match proc_starttime(info.pid) {
            Some(cur) if cur == info.starttime => {}
            _ => {
                return Err(format!(
                    "nkg: stale serve file {path} (pid {} reused); falling back to cold index load",
                    info.pid
                ));
            }
        }
    }
    Ok(Some(info.port))
}

fn cmd_serve(idx_path: &str, port: u16) {
    let idx = Arc::new(load_index_for_serve(idx_path));
    // O3: daemon-global warm-fd cache + fd headroom for one fd per file.
    bump_nofile_for_cache(idx.files.len());
    let fdc = Arc::new(FdCache::new(idx.files.len()));
    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("nkg: bind 127.0.0.1:{port}: {e}");
            std::process::exit(2);
        }
    };
    let bound = listener.local_addr().map(|a| a.port()).unwrap_or(port);
    save_serve_info(idx_path, bound);
    eprintln!(
        "nkg: serving {} files on 127.0.0.1:{bound}",
        idx.files.len()
    );
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for s in listener.incoming().flatten() {
        if active.load(std::sync::atomic::Ordering::SeqCst) >= MAX_SERVE_CONNECTIONS {
            drop(s);
            continue;
        }
        let idx = idx.clone();
        let fdc = fdc.clone();
        let active = active.clone();
        active.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::thread::spawn(move || {
            handle_client(s, idx, fdc);
            active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        });
    }
}
/// MatchFlags half of a serve query (MatchFlags owns; ContextLines owns the
/// before/after half). `pattern` (kept positional) is the combined
/// alternation the matcher compiles; the spec carries the branches for
/// server-side grams/bonus plus the flags.
struct MatchSpec<'a> {
    patterns: &'a [String],
    fixed: bool,
    word: bool,
    invert: bool,
    max_count: Option<usize>,
    qroot: &'a str,
    display_root: &'a str,
}
/// Where a classified hit row goes once the wire row has been read.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ServeMode {
    /// `-q` / `-c` / `-l`: nothing per row. Counts print after the `done`
    /// line, which is where the totals come from.
    Aggregate,
    /// Default JSON: the wire line verbatim.
    Json,
    /// `--format text`: `path:line:text`, rendered as each row arrives.
    Text,
    /// `-A`/`-B`/`-C`: the whole response, regrouped after the stream ends.
    Context,
}

/// Rendered bytes held before a batch reaches stdout.
const SERVE_FLUSH_BYTES: usize = 256 * 1024;

/// Per-row scratch for the streamed text render: the decoded path and text,
/// reused across rows so rendering a hit allocates nothing.
#[derive(Default)]
struct WireScratch {
    path: Vec<u8>,
    text: Vec<u8>,
}

/// One served response, consumed as it streams off the socket. Rows are
/// classified, counted and rendered where they arrive, so neither the
/// response nor its render is ever materialised whole. The `done` line's
/// flags are still read last, after every row — that ordering is unchanged.
struct ServeRows {
    /// In `Context` mode, the raw wire, regrouped by the caller. In the
    /// streaming modes this is drained to stdout and ends up empty.
    buf: Vec<u8>,
    /// Distinct hit paths (wire-escaped) and their hit counts: both the
    /// `-c` / `-l` rows and the `F` in the `N matches in F files` line.
    files: HashMap<Vec<u8>, usize>,
    matches: usize,
    /// The daemon sent its `done` line, so the response ran to completion.
    done: bool,
    /// The daemon echoed `"ctx":true` rows, so it understood the context
    /// fields; an old daemon answered with plain hits.
    ctx_echo: bool,
    verify_err: bool,
    /// Rows already written to stdout. Past the first one a cold re-run
    /// would duplicate them, which is why a mid-response failure is fatal.
    emitted: bool,
}

impl ServeRows {
    /// Sorted `path:count` rows for `-c` / `-l`, decoded from the wire's
    /// escaped paths (cold-path parity: one row per hit file, sorted).
    fn aggregates(&self) -> Vec<(String, usize)> {
        let mut rows: Vec<(String, usize)> = self
            .files
            .iter()
            .map(|(p, n)| {
                let mut dec = Vec::with_capacity(p.len());
                push_unescaped_json(&mut dec, p);
                (String::from_utf8_lossy(&dec).into_owned(), *n)
            })
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        rows
    }

    /// Distinct hit files: the `F` in the `N matches in F files` diagnostics.
    fn matched(&self) -> usize {
        self.files.len()
    }
}

/// Everything a serve fetch needs about the query it is serving: the request
/// fields, how each row is retained, the client-side highlight matcher, and
/// the flags the response tail renders with. Bundled so the fetch entries
/// stay under clippy's argument-count limit (same idiom as `MatchSpec`).
struct ServeQuery<'a> {
    pattern: &'a str,
    top: Option<usize>,
    ignore_case: bool,
    mspec: &'a MatchSpec<'a>,
    /// How a classified row is retained; see `ServeMode`.
    mode: ServeMode,
    /// Client-side highlight matcher for `--format text`; plain fallback when
    /// the matcher will not build (unreachable in practice — a bad regex
    /// exits 2 before render — so a good render never fails for a miss).
    matcher: Option<RegexMatcher>,
    group_sep: &'a str,
    ctx_before: usize,
    ctx_after: usize,
    count_mode: bool,
    files_only: bool,
    quiet: bool,
}

impl ServeQuery<'_> {
    fn ctx_on(&self) -> bool {
        self.ctx_before > 0 || self.ctx_after > 0
    }

    /// The wire request for this query, or None when it will not serialize.
    fn request(&self) -> Option<String> {
        serde_json::to_string(&Query {
            pattern: self.pattern.to_string(),
            top: self.top,
            ignore_case: self.ignore_case,
            before: self.ctx_before,
            after: self.ctx_after,
            word: self.mspec.word,
            invert: self.mspec.invert,
            max_count: self.mspec.max_count,
            patterns: self.mspec.patterns.to_vec(),
            fixed: self.mspec.fixed,
            qroot: self.mspec.qroot.to_string(),
            display_root: self.mspec.display_root.to_string(),
        })
        .ok()
    }
}

/// How a served row is consumed, from the flags alone.
fn serve_mode(
    quiet: bool,
    count_mode: bool,
    files_only: bool,
    ctx_on: bool,
    format_text: bool,
) -> ServeMode {
    // `-q` is an aggregate shape too: it prints nothing, and the `done` line
    // still has to supply the totals the diagnostics use.
    if ctx_on {
        ServeMode::Context
    } else if quiet || count_mode || files_only {
        ServeMode::Aggregate
    } else if format_text {
        ServeMode::Text
    } else {
        ServeMode::Json
    }
}

/// Render a collected wire response as `--format text` rows. Only the
/// `--port` old-daemon degradation reaches this: context was asked for, the
/// daemon did not honour it, and its plain hit rows sit in `rows.buf`.
fn render_buffered_text(raw: &[u8], matcher: Option<&RegexMatcher>) -> Vec<u8> {
    let mut out = vec![];
    let mut scratch = WireScratch::default();
    for line in raw.split(|&b| b == b'\n') {
        if !line.is_empty() {
            push_wire_text_row(&mut out, line, matcher, &mut scratch);
        }
    }
    out
}

/// Served-response tail, shared by `--use-index` and `--port`: print the
/// `-c`/`-l` aggregates or the regrouped context render (JSON and text rows
/// are already on stdout — `read_serve_response` streamed them), then the
/// `N matches in F files` diagnostic, then the exit contract.
fn finish_serve_response(rows: &ServeRows, r: &ServeQuery<'_>, t0: Instant) {
    let matcher = r.matcher.as_ref();
    let matched = rows.matched();
    if r.count_mode || r.files_only {
        // `-c` / `-l` over serve: aggregate the served rows client-side (--top
        // already applied server-side; `-l` wins over `-c`, `-q` still
        // suppresses stdout). `matched` counts distinct hit files (cold
        // parity); diagnostics keep the cold `matches in files` + `index
        // load` shape so stderr needs one grammar (`via serve` rides inside
        // the parens, load is 0 with no cold read).
        if !r.quiet {
            let agg = rows.aggregates();
            let refs: Vec<(&str, usize)> = agg.iter().map(|(p, n)| (p.as_str(), *n)).collect();
            let stdout = std::io::stdout();
            let mut writer = std::io::BufWriter::with_capacity(1024 * 1024, stdout.lock());
            write_aggregates(&mut writer, &refs, r.files_only);
            stdout_flush(&mut writer);
        }
    } else if r.ctx_on() && !r.quiet {
        // Context owns the output: regrouped rg-shaped rows from the carried
        // hit+ctx wire (rank groups kept). `ctx_echo` false means an old
        // daemon ignored the context fields and answered with plain hits,
        // which render as text rows instead (serve-first fails over to cold
        // there; an explicit --port has no cold tree).
        let stdout = std::io::stdout();
        let mut writer = std::io::BufWriter::with_capacity(1024 * 1024, stdout.lock());
        let text = if rows.ctx_echo {
            render_served_context(&rows.buf, r.ctx_before, r.ctx_after, r.group_sep, matcher)
        } else {
            render_buffered_text(&rows.buf, matcher)
        };
        stdout_write_all(&mut writer, &text);
        stdout_flush(&mut writer);
    }
    eprintln!(
        "nkg: {} matches in {matched} files, {} ms (index load 0 ms via serve)",
        rows.matches,
        t0.elapsed().as_millis()
    );
    if rows.verify_err {
        std::process::exit(2);
    }
    if rows.matches == 0 {
        std::process::exit(1);
    }
}
/// Why a serve read stopped before the `done` line.
#[derive(Debug)]
struct ServeFail {
    msg: String,
    /// The daemon rejected the pattern rather than dying.
    bad_regex: bool,
    /// Rows already reached stdout, so the caller must not re-run cold.
    emitted: bool,
}

/// Append `path:line:text` for one served wire row. Framing is
/// `emit_text_row`'s, so the streamed render and the cold render cannot
/// diverge; only the field split differs (by position, not by parse).
fn push_wire_text_row(
    out: &mut Vec<u8>,
    wire: &[u8],
    matcher: Option<&RegexMatcher>,
    scratch: &mut WireScratch,
) {
    let Some(row) = scan_wire_row(wire) else {
        return; // unparseable line: skipped, exactly as before
    };
    scratch.path.clear();
    push_unescaped_json(&mut scratch.path, row.path);
    scratch.text.clear();
    push_unescaped_json(&mut scratch.text, row.text);
    // Wire text was escaped from a `&str`, so the decoded bytes are valid
    // UTF-8; the lossy arm is the degradation the cold renderer already
    // accepts (`banked_slice`), not a new failure mode.
    let path = String::from_utf8_lossy(&scratch.path);
    let text = String::from_utf8_lossy(&scratch.text);
    match matcher {
        Some(m) => emit_text_row_colored(out, &path, row.line, &text, m),
        None => emit_text_row(out, &path, row.line, &text),
    }
}

/// Read one served response off `stream`, rendering rows as they arrive.
///
/// `Err` means the daemon stopped early. It is only safe to fall back to a
/// cold re-run when `emitted` is false: past the first row the partial
/// output is already on stdout and the re-run would duplicate it, which is a
/// worse failure than exit 2. Every failure that can happen before the first
/// row (connect, request write, an `{"error":...}` reply) still falls back
/// exactly as it did when the whole response was collected first.
fn read_serve_response(
    stream: &mut impl Read,
    mode: ServeMode,
    matcher: Option<&RegexMatcher>,
    out: &mut impl Write,
) -> Result<ServeRows, ServeFail> {
    let mut reader = BufReader::new(stream);
    let mut rows = ServeRows {
        buf: vec![],
        files: HashMap::new(),
        matches: 0,
        done: false,
        ctx_echo: false,
        verify_err: false,
        emitted: false,
    };
    let mut line = String::new();
    let mut scratch = WireScratch::default();
    loop {
        line.clear();
        let read = match reader.read_line(&mut line) {
            Err(e) => {
                return Err(ServeFail {
                    msg: e.to_string(),
                    bad_regex: false,
                    emitted: rows.emitted,
                });
            }
            Ok(0) => break,
            Ok(n) => n,
        };
        let t = line.trim();
        if t.contains("\"done\"") {
            rows.done = true;
            rows.ctx_echo = t.contains("\"ctx\":true");
            rows.verify_err = t.contains("\"verify_error\"");
            break;
        }
        if t.contains("\"error\"") {
            return Err(ServeFail {
                msg: t
                    .find("\"error\":\"")
                    .map(|s| {
                        let rest = &t[s + 9..];
                        rest.strip_suffix("\"}").unwrap_or(rest).to_string()
                    })
                    .unwrap_or_default(),
                bad_regex: true,
                emitted: rows.emitted,
            });
        }
        if t.is_empty() {
            continue;
        }
        let wire = &line.as_bytes()[..read - 1];
        // `"ctx":true` keys off FIELD POSITION, never presence: the marker is
        // the last field of a carried context row, so the same sequence
        // sitting inside a match's own `text` cannot reach it. A parsed test
        // would be equally correct but is the generic-Value walk this loop
        // exists to stop doing; a substring test would be neither.
        if wire.ends_with(br#","ctx":true}"#) {
            if mode == ServeMode::Context {
                rows.buf.extend_from_slice(line.as_bytes());
            }
            continue;
        }
        rows.matches += 1;
        if let Some(row) = scan_wire_row(wire) {
            *rows.files.entry(row.path.to_vec()).or_default() += 1;
        }
        match mode {
            ServeMode::Context | ServeMode::Json => rows.buf.extend_from_slice(line.as_bytes()),
            ServeMode::Text => push_wire_text_row(&mut rows.buf, wire, matcher, &mut scratch),
            ServeMode::Aggregate => {}
        }
        // The streaming modes write each batch out as it fills, so the
        // client never holds the response — or its render — whole.
        if mode != ServeMode::Context && rows.buf.len() >= SERVE_FLUSH_BYTES {
            stdout_write_all(out, &rows.buf);
            rows.buf.clear();
            rows.emitted = true;
        }
    }
    if mode != ServeMode::Context && !rows.buf.is_empty() {
        stdout_write_all(out, &rows.buf);
        rows.buf.clear();
        rows.emitted = true;
    }
    stdout_flush(out);
    Ok(rows)
}

/// Hot `--port` fetch: read the served response, rendering it as it arrives.
/// An explicit `--port` has no cold tree to fall back to, so every failure
/// here is terminal — including one that arrives after rows are printed.
fn client_query(port: u16, q: &ServeQuery<'_>) -> ServeRows {
    let mut stream = match TcpStream::connect(("127.0.0.1", port)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("nkg: connect 127.0.0.1:{port}: {e}");
            std::process::exit(2);
        }
    };
    let Some(req) = q.request() else {
        eprintln!("nkg: serve write 127.0.0.1:{port}: bad request");
        std::process::exit(2);
    };
    if let Err(e) = stream
        .write_all(req.as_bytes())
        .and(stream.write_all(b"\n"))
    {
        eprintln!("nkg: serve write 127.0.0.1:{port}: {e}");
        std::process::exit(2);
    }
    let stdout = std::io::stdout();
    let mut writer = std::io::BufWriter::with_capacity(SERVE_FLUSH_BYTES, stdout.lock());
    match read_serve_response(&mut stream, q.mode, q.matcher.as_ref(), &mut writer) {
        Ok(rows) => rows,
        Err(f) => {
            if f.bad_regex {
                eprintln!("nkg: bad regex: {}", f.msg);
            } else {
                eprintln!("nkg: serve read 127.0.0.1:{port}: {}", f.msg);
            }
            std::process::exit(2);
        }
    }
}

/// Serve-first probe for `--use-index`: connect to the daemon registered in
/// `<index>.serve.json`, if any. No sidecar (or an unparseable one) is a
/// silent cold fallback; a stale registration warns once via `load_serve_port_quiet`;
/// any failure after a live registration (no listener, bad reply, old daemon
/// without context echo) warns once as unreachable. At most one line total.
/// Context behaves like `client_query`: carried `"ctx":true` lines collect
/// verbatim but never count, and a missing context echo from an old daemon
/// fails over to the cold path — which is safe, because no context or
/// aggregate row is on stdout until the response has ended. A default-JSON or
/// text query has already printed its rows by then, so an incomplete
/// response there exits 2 instead of re-running cold over partial output.
fn try_serve_query(idx_path: &str, q: &ServeQuery<'_>) -> ServeProbe {
    const UNREACHABLE: &str = "nkg: server unreachable, falling back to local index";
    let port = match load_serve_port_quiet(idx_path) {
        Ok(Some(p)) => p,
        Ok(None) => return ServeProbe::MissSilent,
        Err(msg) => return ServeProbe::MissWarn(msg),
    };
    let addr = match "127.0.0.1"
        .parse()
        .ok()
        .map(|ip| std::net::SocketAddr::new(ip, port))
    {
        Some(a) => a,
        None => return ServeProbe::MissWarn(UNREACHABLE.to_string()),
    };
    let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
        Ok(s) => s,
        Err(_) => return ServeProbe::MissWarn(UNREACHABLE.to_string()),
    };
    if stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .is_err()
    {
        return ServeProbe::MissWarn(UNREACHABLE.to_string());
    }
    let Some(req) = q.request() else {
        return ServeProbe::MissWarn(UNREACHABLE.to_string());
    };
    if stream.write_all(req.as_bytes()).is_err() || stream.write_all(b"\n").is_err() {
        return ServeProbe::MissWarn(UNREACHABLE.to_string());
    }
    let stdout = std::io::stdout();
    let mut writer = std::io::BufWriter::with_capacity(SERVE_FLUSH_BYTES, stdout.lock());
    let rows = match read_serve_response(&mut stream, q.mode, q.matcher.as_ref(), &mut writer) {
        Ok(rows) => rows,
        Err(f) if f.emitted => {
            eprintln!("nkg: {}", f.msg);
            std::process::exit(2);
        }
        Err(_) => return ServeProbe::MissWarn(UNREACHABLE.to_string()),
    };
    if !rows.done || (q.mode == ServeMode::Context && !rows.ctx_echo) {
        // Either the daemon stopped before its `done` line, or (context only)
        // an old daemon ignored the context fields and served plain hits. Fall
        // over to the cold path, which attaches context locally — but only if
        // nothing has been printed, which `emitted` proves.
        return if rows.emitted {
            eprintln!("nkg: server closed the connection mid-response");
            std::process::exit(2);
        } else {
            ServeProbe::MissWarn(UNREACHABLE.to_string())
        };
    }
    ServeProbe::Hit(rows)
}
/// Cold-emission JSON string escaper (Escaper region): byte-identical to
/// serde_json for `&str` input. Only `"`, `\` and bytes < 0x20 escape;
/// `\n`/`\r`/`\t`/0x08/0x0C use short forms, other controls `\u00XX`
/// (lowercase hex, matching serde_json); UTF-8 multibyte passes through.
/// memchr2 skips the common quote/backslash-free run; the gap holds only
/// rare controls, scanned inline. Floats are NOT touched here: callers format
/// `score` via serde_json so ryu output stays byte-exact.
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
/// Manual u64 digits, byte-identical to Display, no fmt machinery per hit.
fn push_line_no(buf: &mut Vec<u8>, line: u64) {
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
}
/// Resolve the display path for a file id: index table when indexed, else scan table.
fn path_of<'a>(
    idx_opt: &'a Option<Index>,
    ptab: &'a [String],
    hits_indexed: bool,
    pid: usize,
) -> &'a str {
    match idx_opt {
        Some(idx) if hits_indexed => &idx.files[pid],
        _ => &ptab[pid],
    }
}

// Emission shape shared by all three renderers (context, text, JSON). The
// cost of emitting is matched bytes, not rows: 240 rows of 560 KB out-weigh
// 51k rows of 40 B by three orders of magnitude. A row-count gate therefore
// serialised the byte-heavy half of the space, and a row-count chunk handed
// that half to a single worker (240 rows fit in one 4096-row chunk). Below
// EMIT_PAR_MIN_BYTES of estimated output the rayon barrier plus the per-chunk
// allocations cost more than the rendering they split, so one serial buffer
// wins; above it the rows go through `par_chunks` and are written back in
// `ord` order. EMIT_CHUNK_MAX_ROWS keeps the many-short-rows shape on the
// 4096-row chunk it has always used.
const EMIT_PAR_MIN_BYTES: usize = 64 * 1024;
const EMIT_CHUNK_BYTES: usize = 1024 * 1024;
const EMIT_CHUNK_MAX_ROWS: usize = 4096;
/// Per-row framing estimate: path, line number, separators. JSON also
/// escapes the text and prints the score, hence its larger constant. These
/// are the pre-existing `* 128` / `* 160` reserves, now one term of a byte
/// total rather than the whole estimate.
const FRAME_TEXT: usize = 128;
const FRAME_JSON: usize = 160;

/// Display state every row renderer needs: the banked hits, the flat row
/// index, and how a file id resolves to its display path. Bundled so the
/// renderers stay under clippy's argument-count limit (same contract as
/// `VerifyInput`).
struct EmitSource<'a> {
    hits: &'a [FileHits],
    loc: &'a [(u32, u32)],
    idx_opt: &'a Option<Index>,
    ptab: &'a [String],
    hits_indexed: bool,
    color_on: bool,
    matcher: &'a RegexMatcher,
}

impl EmitSource<'_> {
    fn path(&self, pid: usize) -> &str {
        path_of(self.idx_opt, self.ptab, self.hits_indexed, pid)
    }
}

/// Estimated output bytes for `rows`: the banked match text they decode to
/// plus the per-row framing cost. `HitMeta::start..end` is exactly the banked
/// span, so this is the emitted text volume and not the file's whole arena —
/// `--top` over a large banked file emits a fraction of it. O(rows), no
/// allocation.
fn est_output_bytes(rows: &[u32], hits: &[FileHits], loc: &[(u32, u32)], frame: usize) -> usize {
    let text: usize = rows
        .iter()
        .map(|&i| {
            let (fi, mi) = loc[i as usize];
            let m = &hits[fi as usize].metas[mi as usize];
            (m.end - m.start) as usize
        })
        .sum();
    text + rows.len() * frame
}

/// Rows per parallel chunk for `rows` rows of `est_bytes` estimated output,
/// or `None` to render one serial buffer. The chunk is sized by bytes, so a
/// row that is a large fraction of EMIT_CHUNK_BYTES stands alone and reaches
/// its own worker, while short rows fall back to the row-capped chunking.
fn emit_plan(rows: usize, est_bytes: usize) -> Option<usize> {
    if rows == 0 || est_bytes < EMIT_PAR_MIN_BYTES {
        return None;
    }
    let avg = (est_bytes / rows).max(1);
    Some((EMIT_CHUNK_BYTES / avg).clamp(1, EMIT_CHUNK_MAX_ROWS))
}

/// Upper bound on the bytes one context group renders. Every window a group
/// prints lies inside `[first hit - before, last hit + after]`, and on this
/// path the arena holds whole files, so the line-start table gives that span
/// in O(1) — no window pass, no per-row allocation.
fn ctx_group_bytes(
    fh: &FileHits,
    mis: &[usize],
    before: usize,
    after: usize,
    frame: usize,
) -> usize {
    let (Some(&first), Some(&last)) = (mis.first(), mis.last()) else {
        return 0;
    };
    let nlines = fh.line_starts.len() as u64;
    let lo = fh.metas[first].line.saturating_sub(before as u64).max(1);
    let hi = (fh.metas[last].line + after as u64).min(nlines);
    if hi < lo {
        return 0;
    }
    let s = if lo > 1 {
        fh.line_starts[(lo - 1) as usize]
    } else {
        0
    } as usize;
    let e = if hi < nlines {
        fh.line_starts[hi as usize] as usize
    } else {
        fh.arena.len()
    };
    e.saturating_sub(s) + (hi - lo + 1) as usize * frame
}

/// One chunk of ranked text rows into its own buffer, reserved from the same
/// byte estimate the gate uses. `--color always` is a branch inside this
/// body, so it inherits the gate, the chunking and the reservation.
fn render_text_chunk(src: &EmitSource<'_>, chunk: &[u32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(est_output_bytes(chunk, src.hits, src.loc, FRAME_TEXT));
    for &i in chunk {
        let (fi, mi) = src.loc[i as usize];
        let fh = &src.hits[fi as usize];
        let m = &fh.metas[mi as usize];
        let ps = src.path(fh.pid as usize);
        let text = banked_text(fh, m);
        if src.color_on {
            emit_text_row_colored(&mut buf, ps, m.line, &text, src.matcher);
        } else {
            emit_text_row(&mut buf, ps, m.line, &text);
        }
    }
    buf
}

/// One chunk of ranked JSON rows into its own buffer. Sequential and
/// chunked-parallel emission share this body, so both stay byte-identical.
fn render_json_chunk(src: &EmitSource<'_>, esc: &[Option<Vec<u8>>], chunk: &[u32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(est_output_bytes(chunk, src.hits, src.loc, FRAME_JSON));
    for &i in chunk {
        let (fi, mi) = src.loc[i as usize];
        let fh = &src.hits[fi as usize];
        let m = &fh.metas[mi as usize];
        emit_raw_with_path(
            &mut buf,
            esc[fh.pid as usize].as_ref().unwrap(),
            m.line,
            &banked_text(fh, m),
            m.score,
        );
    }
    buf
}

/// One chunk of context file groups into its own buffer. The chunk unit is
/// the file group — a group's rows share the hit cursor and print in line
/// order — so groups partition the output and `collect()` keeps them in rank
/// order.
fn render_ctx_chunk(
    src: &EmitSource<'_>,
    chunk: &[(usize, Vec<usize>)],
    before: usize,
    after: usize,
    sep: &str,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        chunk
            .iter()
            .map(|(fi, mis)| ctx_group_bytes(&src.hits[*fi], mis, before, after, FRAME_TEXT))
            .sum(),
    );
    for (fi, mis) in chunk {
        let fh = &src.hits[*fi];
        let ps = src.path(fh.pid as usize);
        let nlines = fh.line_starts.len() as u64;
        let mlines = ctx_group_lines(src.hits, *fi, mis);
        let mut k = 0usize;
        let mut first_group = true;
        for (lo, hi) in compute_groups(&mlines, before, after) {
            if !first_group && !sep.is_empty() {
                buf.extend_from_slice(sep.as_bytes());
                buf.push(b'\n');
            }
            first_group = false;
            let hi = hi.min(nlines);
            let mut ln = lo;
            while ln <= hi {
                if k < mis.len() && fh.metas[mis[k]].line == ln {
                    let m = &fh.metas[mis[k]];
                    let text = banked_text(fh, m);
                    if src.color_on {
                        emit_text_row_colored(&mut buf, ps, ln, &text, src.matcher);
                    } else {
                        emit_text_row(&mut buf, ps, ln, &text);
                    }
                    k += 1;
                    while k < mis.len() && fh.metas[mis[k]].line == ln {
                        k += 1;
                    }
                } else {
                    let text = ctx_line_text(fh, ln);
                    emit_ctx_row(&mut buf, ps, ln, &text);
                }
                ln += 1;
            }
        }
    }
    buf
}

/// Manual cold-emission line from columnar fields: byte-identical to the
/// derived Serialize impl (same field order/separators, same path escaper,
/// same serde/ryu score path); only the source of the fields differs.
fn emit_raw_with_path(buf: &mut Vec<u8>, path_esc: &[u8], line: u64, text: &str, score: f64) {
    buf.extend_from_slice(b"{\"path\":\"");
    buf.extend_from_slice(path_esc);
    buf.extend_from_slice(b"\",\"line\":");
    push_line_no(buf, line);
    buf.extend_from_slice(b",\"text\":\"");
    push_escaped_json(buf, text);
    buf.extend_from_slice(b"\",\"score\":");
    serde_json::to_writer(&mut *buf, &score).unwrap();
    buf.extend_from_slice(b"}\n");
}
/// Grep-compatible text line (`--format text`): `path:line:text` in rank
/// order — the same hits in the same order as JSON, only rendered without
/// score. Line numbers are always on; text is the same banked decode as
/// JSON, unescaped. ColorOut's hook point: wrap the text push below.
fn emit_text_row(buf: &mut Vec<u8>, path: &str, line: u64, text: &str) {
    buf.extend_from_slice(path.as_bytes());
    buf.push(b':');
    push_line_no(buf, line);
    buf.push(b':');
    buf.extend_from_slice(text.as_bytes());
    buf.push(b'\n');
}

/// Context row (`-A`/`-B`/`-C`): `path:line-text` — the `-` marker mirrors
/// rg's context-line shape (probed on 15.1.0: `:` match vs `-` context, `--`
/// between disjoint in-file groups). Framing duplicates `emit_text_row`
/// (the file's itoa convention); only the marker differs.
fn emit_ctx_row(buf: &mut Vec<u8>, path: &str, line: u64, text: &str) {
    buf.extend_from_slice(path.as_bytes());
    buf.push(b':');
    push_line_no(buf, line);
    buf.push(b'-');
    buf.extend_from_slice(text.as_bytes());
    buf.push(b'\n');
}

/// Serve-wire context line: same fields as `emit_raw_with_path` plus a
/// trailing `,"ctx":true` marker, so clients can tell carried context from
/// hits without reparsing ambiguity (a match *text* may itself contain the
/// substring `"ctx":true`). `score` carries the file score (context inherits
/// its file's rank weight; clients drop it at render). Only ever emitted
/// when the query asked for context, so the default wire is untouched.
fn emit_ctx_json(buf: &mut Vec<u8>, path_esc: &[u8], line: u64, text: &str, file_score: f64) {
    buf.extend_from_slice(b"{\"path\":\"");
    buf.extend_from_slice(path_esc);
    buf.extend_from_slice(b"\",\"line\":");
    push_line_no(buf, line);
    buf.extend_from_slice(b",\"text\":\"");
    push_escaped_json(buf, text);
    buf.extend_from_slice(b"\",\"score\":");
    serde_json::to_writer(&mut *buf, &file_score).unwrap();
    buf.extend_from_slice(b",\"ctx\":true}\n");
}

/// Serve-wire context render (ContextLines): the daemon returns hits plus
/// carried `"ctx":true` lines in rank-file group order. Regroup the hit
/// lines (first-seen file order, lines ascending — the wire already arrives
/// so), expand/merge windows with `compute_groups`, and print rg-shaped
/// rows (`path:line:text` hits, `path:line-text` context, `sep` between
/// disjoint in-file groups, none across files). Same groups the cold
/// renderer prints from the same hit set; unparseable lines are skipped,
/// mirroring `served_path_counts`. A line that is both hit and context
/// renders as a hit.
fn render_served_context(
    raw: &[u8],
    before: usize,
    after: usize,
    sep: &str,
    matcher: Option<&RegexMatcher>,
) -> Vec<u8> {
    // path -> (line -> (text, is_hit)), first-seen file order.
    type ServedFileLines = (String, std::collections::BTreeMap<u64, (String, bool)>);
    let mut files: Vec<ServedFileLines> = vec![];
    for line in raw.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(line) {
            if let (Some(p), Some(n), Some(t)) = (
                v.get("path").and_then(|p| p.as_str()),
                v.get("line").and_then(|l| l.as_u64()),
                v.get("text").and_then(|t| t.as_str()),
            ) {
                let hit = !v.get("ctx").and_then(|c| c.as_bool()).unwrap_or(false);
                let idx = match files.iter().position(|(fp, _)| fp == p) {
                    Some(i) => i,
                    None => {
                        files.push((p.to_string(), std::collections::BTreeMap::new()));
                        files.len() - 1
                    }
                };
                files[idx]
                    .1
                    .entry(n)
                    .and_modify(|e| e.1 = e.1 || hit)
                    .or_insert_with(|| (t.to_string(), hit));
            }
        }
    }
    let mut out = Vec::with_capacity(raw.len());
    for (path, lines) in &files {
        let hits: Vec<u64> = lines
            .iter()
            .filter(|(_, (_, h))| *h)
            .map(|(n, _)| *n)
            .collect();
        let mut first_group = true;
        for (lo, hi) in compute_groups(&hits, before, after) {
            if !first_group && !sep.is_empty() {
                out.extend_from_slice(sep.as_bytes());
                out.push(b'\n');
            }
            first_group = false;
            // No EOF clamp available (nlines isn't on the wire): lines past
            // EOF simply have no entry and are skipped — output-identical to
            // clamping, by the same merge argument as `compute_groups`.
            let mut ln = lo;
            while ln <= hi {
                if let Some((text, hit)) = lines.get(&ln) {
                    if *hit {
                        if let Some(m) = matcher {
                            emit_text_row_colored(&mut out, path, ln, text, m);
                        } else {
                            emit_text_row(&mut out, path, ln, text);
                        }
                    } else {
                        emit_ctx_row(&mut out, path, ln, text);
                    }
                }
                if ln == u64::MAX {
                    break;
                }
                ln += 1;
            }
        }
    }
    out
}

/// --color target state (ColorOut): auto (default), always, never, plus ansi
/// as an rg-compatible alias for always. auto colorizes only when stdout is
/// a TTY. Color applies to `--format text` match spans only; JSON stays
/// machine-clean. GREP_COLORS is parked (not honored): match style is fixed
/// bold-red, byte-probed on rg 15.1.0.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ColorWhen {
    Auto,
    Always,
    Never,
}

/// Parse a `--color` value; None means usage error (exit 2 at the call site).
/// `ansi` is an rg-compatible alias for `always`.
fn parse_color_when(s: &str) -> Option<ColorWhen> {
    match s {
        "auto" => Some(ColorWhen::Auto),
        "always" | "ansi" => Some(ColorWhen::Always),
        "never" => Some(ColorWhen::Never),
        _ => None,
    }
}

/// Resolve color for this process. Explicit always wins everywhere (even
/// piped); never wins nowhere; auto follows the stdout TTY only.
fn color_enabled(when: ColorWhen) -> bool {
    match when {
        ColorWhen::Always => true,
        ColorWhen::Never => false,
        ColorWhen::Auto => std::io::stdout().is_terminal(),
    }
}

/// Wrap each non-empty matcher span in `text` with rg's match style
/// (`\x1b[0m\x1b[1m\x1b[31m` … `\x1b[0m`). Zero-width matches are skipped so
/// patterns like `x*` never spray codes; a line with no spans borrows back
/// unchanged. Byte splicing is safe: regex spans are char-boundary aligned.
fn colorize_spans<'a>(text: &'a str, matcher: &RegexMatcher) -> std::borrow::Cow<'a, str> {
    use grep_matcher::Matcher;
    let b = text.as_bytes();
    let mut spans: Vec<(usize, usize)> = vec![];
    let _ = matcher.find_iter(b, |m| {
        if m.start() < m.end() {
            spans.push((m.start(), m.end()));
        }
        true
    });
    if spans.is_empty() {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = Vec::with_capacity(b.len() + spans.len() * 16);
    let mut pos = 0usize;
    for (s, e) in spans {
        out.extend_from_slice(&b[pos..s]);
        out.extend_from_slice(b"\x1b[0m\x1b[1m\x1b[31m");
        out.extend_from_slice(&b[s..e]);
        out.extend_from_slice(b"\x1b[0m");
        pos = e;
    }
    out.extend_from_slice(&b[pos..]);
    // Spans are char-boundary aligned and SGR inserts are ASCII, so the
    // splice stays valid UTF-8 by construction; loud panic if broken.
    std::borrow::Cow::Owned(String::from_utf8(out).expect("colorize splice must stay UTF-8"))
}

/// Colored text row: same `path:line:text` framing as `emit_text_row` with
/// match spans highlighted. Delegates framing so the two never diverge.
fn emit_text_row_colored(
    buf: &mut Vec<u8>,
    path: &str,
    line: u64,
    text: &str,
    matcher: &RegexMatcher,
) {
    let colored = colorize_spans(text, matcher);
    emit_text_row(buf, path, line, &colored);
}

// Real emission fns (`emit_raw_with_path` + `push_escaped_json`) are exercised
// directly by the escape check below; no test-only wrappers.

const USAGE: &str = "usage: nkg index <path> [--index FILE]\n       nkg serve --index FILE --port PORT\n       nkg [-i] [-v] [-w] [-F] [-m N] [-e PAT] [-f FILE] [-q] [-c] [-l] [-./--hidden] [--no-ignore] [-L/--follow] [-g/--glob GLOB] [-d/--max-depth N] [--max-filesize N] [-A N] [-B N] [-C N] [--group-separator SEP] [--top N] [--format json|text] [--color[=WHEN]] [--use-index FILE | --port PORT] [--] <pattern> [path]\n";

fn usage() -> ! {
    eprint!("{USAGE}");
    std::process::exit(2);
}
/// Stdout BrokenPipe contract: `| head` exits 0; any other IO error exits 2.
fn stdout_err(e: std::io::Error) -> ! {
    if e.kind() == std::io::ErrorKind::BrokenPipe {
        std::process::exit(0);
    }
    eprintln!("nkg: stdout: {e}");
    std::process::exit(2);
}

/// Stdout write that never panics; success-path bytes are unchanged.
fn stdout_write_all(w: &mut impl Write, data: &[u8]) {
    if let Err(e) = w.write_all(data) {
        stdout_err(e);
    }
}

/// Stdout flush with the same BrokenPipe contract as `stdout_write_all`.
fn stdout_flush(w: &mut impl Write) {
    if let Err(e) = w.flush() {
        stdout_err(e);
    }
}
/// `-q` exit: stdout stays empty (the flag's whole contract), stderr keeps
/// the diagnostics line: exit 2 on any walk error, else 0 on the first
/// match / 1 on none. The
/// short-circuit is the caller's `find_any`: rayon stops scheduling verify
/// work once any worker banks a hit, so quiet latency is time-to-first-hit.
fn quiet_exit(found: bool, files: usize, load_ms: u128, t0: Instant, walk_error: bool) -> ! {
    eprintln!(
        "nkg: {} in {files} files, {} ms (index load {load_ms} ms)",
        if found { "1+ matches" } else { "0 matches" },
        t0.elapsed().as_millis()
    );
    std::process::exit(if walk_error {
        2
    } else if found {
        0
    } else {
        1
    });
}

/// `--help` text (stdout, exit 0). Usage errors still go through `usage()`
/// (stderr, exit 2). Write errors are ignored: help under a closed pipe
/// simply ends the process.
fn print_help() {
    let head = concat!(
        "nkg ",
        env!("CARGO_PKG_VERSION"),
        " — ranked trigram code search\n",
    );
    let opts = concat!(
        "options:\n",
        "  -i, --ignore-case  case-insensitive match\n",
        "  -q, --quiet        suppress stdout, stop at first match\n",
        "  --silent           alias for --quiet\n",
        "  -                  read (standard input) instead of [path]\n",
        "                     (no [path]: search . when stdin is a terminal,\n",
        "                      else search stdin as one unit)\n",
        "  -c, --count        path:count per matching file, path-sorted\n",
        "  -l, --files-with-matches\n",
        "  --stats           print the query plan and candidate counts to\n",
        "                     stderr (indexed searches only)\n",
        "  -m, --max-count N  cap matching lines per file at N (0 matches\n",
        "                     nothing; -c prints capped counts; applies\n",
        "                     per-file before --top)\n",
        "  -e, --regexp PAT   search pattern, OR (repeatable; an inline flag\n",
        "                     like (?i) stays scoped to its pattern; any -e/-f\n",
        "                     makes every positional a path)\n",
        "  -f, --file FILE    patterns from FILE, one per line (repeatable;\n",
        "                     empty line matches every line; - reads stdin;\n",
        "                     missing file exits 2)\n",
        "  -F, --fixed-strings\n",
        "                     treat all patterns literally\n",
        "  -v, --invert-match select non-matching lines (forces full scan\n",
        "                     under --use-index)\n",
        "  -w, --word-regexp  word-boundary match (Unicode word chars)\n",
        "                     (short no-arg flags combine: any cluster of only\n",
        "                     i q c l F v w letters sums its letters)\n",
        "  --format json|text output rendering (default json; text emits\n",
        "                     path:line:text in rank order — same hits, same\n",
        "                     order as json, no score; ignored under -c/-l/-q)\n",
        "  --color[=WHEN]     highlight match spans in --format text (default auto:\n",
        "                     colorize only when stdout is a tty; always/never force\n",
        "                     or suppress; ansi aliases always; json stays clean;\n",
        "                     GREP_COLORS not honored)\n",
        "  -., --hidden       search hidden files and directories\n",
        "  --no-ignore        skip .gitignore/.ignore/.rgignore/exclude files\n",
        "  -L, --follow       follow symbolic links\n",
        "  -g, --glob GLOB    include/exclude paths, gitignore-style (repeatable;\n",
        "                     leading ! excludes, neg-only keeps the rest)\n",
        "  -d, --max-depth N  limit directory traversal depth\n",
        "  --max-filesize N   skip files larger than N bytes (K/M/G suffixes)\n",
        "  -A, --after-context N\n",
        "                     print N lines after each match (`-A2` also works)\n",
        "  -B, --before-context N\n",
        "                     print N lines before each match (`-B2` also works)\n",
        "  -C, --context N    print N lines around each match (`-C1` also works;\n",
        "                     an explicit -A/-B beats -C on its side)\n",
        "  --group-separator SEP\n",
        "                     separator between disjoint context groups in one\n",
        "                     file (default `--`; empty prints none)\n",
        "  --top N            print only the top N ranked matches\n",
        "  --use-index FILE   load this index file for the query, consulting the\n",
        "                     daemon registered for it first and falling back to a\n",
        "                     local index load when the server is unreachable\n",
        "  --port PORT        query the daemon on PORT instead of searching locally\n",
        "  --                 end the flag scan, so a pattern beginning with -\n",
        "                     is searched literally\n",
        "  --index FILE       for index and serve, use FILE as the index file\n",
        "                     (default: .nkg.bin)\n",
        "  -h, --help         print help to stdout and exit 0\n",
        "  -V, --version      print the version to stdout and exit 0\n",
    );
    let stdout = std::io::stdout();
    let mut w = stdout.lock();
    let _ = w.write_all(head.as_bytes());
    let _ = w.write_all(USAGE.as_bytes());
    let _ = w.write_all(opts.as_bytes());
    let _ = w.flush();
}

/// `--version` (stdout, exit 0); same closed-pipe tolerance as help.
fn print_version() {
    let stdout = std::io::stdout();
    let mut w = stdout.lock();
    let _ = writeln!(w, "nkg {}", env!("CARGO_PKG_VERSION"));
}

fn main() {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    // --help/--version win before any subcommand; `--` ends the flag scan
    // so `nkg -- --help` still searches the literal.
    {
        let mut dashdash = false;
        for a in &raw {
            if dashdash {
                break;
            }
            if a == "--" {
                dashdash = true;
            } else if a == "--help" || a == "-h" {
                print_help();
                return;
            } else if a == "--version" || a == "-V" {
                print_version();
                return;
            }
        }
    }
    if raw.first().map(|s| s.as_str()) == Some("index") {
        if raw.len() < 2 {
            usage();
        }
        let root = PathBuf::from(&raw[1]);
        let mut idx = String::from(".nkg.bin");
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
        let mut idx = String::from(".nkg.bin");
        let mut port: u16 = 0;
        let mut have_port = false;
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
                    eprintln!("nkg: bad --port {:?}: expected a port number", raw[j]);
                    usage();
                }
                have_port = true;
            }
            j += 1;
        }
        // `--port` is required (usage exit 2). The old random-bind
        // (port 0) is gone: no caller relies on it; only this site
        // called `cmd_serve`.
        if !have_port {
            usage();
        }
        cmd_serve(&idx, port);
        return;
    }
    let mut top: Option<usize> = None;
    let mut use_index: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut ignore_case = false;
    let mut quiet = false;
    let mut count_mode = false;
    let mut files_only = false;
    let mut format_text = false;
    let mut color_when = ColorWhen::Auto;
    let mut walk_hidden = false;
    let mut walk_no_ignore = false;
    let mut walk_follow = false;
    let mut walk_max_depth: Option<usize> = None;
    let mut walk_max_filesize: Option<u64> = None;
    let mut walk_globs: Vec<String> = vec![];
    // Context flags (ContextLines): three Options so an explicit -A/-B beats
    // -C regardless of order (probed on rg 15.1.0: `-C1 -A3` and `-A3 -C1`
    // both yield after=3). Resolved to before/after after the loop.
    let mut ctx_a: Option<usize> = None;
    let mut ctx_b: Option<usize> = None;
    let mut ctx_c: Option<usize> = None;
    // MatchFlags (-m/-e/-f/-F/-v/-w): patterns accumulate from `-e` repeats
    // and `-f` files; any of them makes every positional a path.
    // `-x`/`-P`/`-E`/`-G` are parked (loud exit 2, never positional).
    let mut max_count: Option<usize> = None;
    let mut patterns_e: Vec<String> = vec![];
    let mut pattern_files: Vec<String> = vec![];
    let mut explicit_patterns = false;
    let mut fixed_strings = false;
    let mut invert_match = false;
    let mut word_regexp = false;
    // Group separator between disjoint in-file context groups (nkg
    // extension — rg 15.1.0 has no such flag but prints `--`); empty means
    // no separator lines.
    let mut group_sep = String::from("--");
    let mut pos: Vec<String> = vec![];
    let mut end_opts = false;
    let mut i = 0;
    while i < raw.len() {
        if !end_opts && raw[i] == "--" {
            end_opts = true;
            i += 1;
            continue;
        }
        if end_opts {
            pos.push(raw[i].clone());
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
                eprintln!("nkg: bad --top {:?}: expected a number", raw[i]);
                usage();
            }
        } else if raw[i].starts_with("--top=") {
            match raw[i]["--top=".len()..].parse::<usize>() {
                Ok(n) => top = Some(n),
                Err(_) => {
                    eprintln!("nkg: bad --top {:?}: expected a number", raw[i]);
                    usage();
                }
            }
        } else if raw[i] == "--use-index" {
            i += 1;
            if i >= raw.len() {
                usage();
            }
            use_index = Some(raw[i].clone());
        } else if raw[i] == "--format" {
            i += 1;
            if i >= raw.len() {
                usage();
            }
            match raw[i].as_str() {
                "text" => format_text = true,
                "json" => format_text = false,
                _ => {
                    eprintln!("nkg: bad --format {:?}: expected json|text", raw[i]);
                    usage();
                }
            }
        } else if raw[i].starts_with("--format=") {
            match &raw[i]["--format=".len()..] {
                "text" => format_text = true,
                "json" => format_text = false,
                _ => {
                    eprintln!("nkg: bad --format {:?}: expected json|text", raw[i]);
                    usage();
                }
            }
        } else if raw[i] == "--color" {
            // Bare --color forces on (GNU `[=WHEN]` convention; rg requires a
            // value, so bare is the one deliberate divergence). A following
            // valid WHEN is consumed as the value (`--color always`); anything
            // else stays positional (the pattern).
            if i + 1 < raw.len() && parse_color_when(&raw[i + 1]).is_some() {
                i += 1;
                color_when = parse_color_when(&raw[i]).unwrap();
            } else {
                color_when = ColorWhen::Always;
            }
        } else if raw[i].starts_with("--color=") {
            match parse_color_when(&raw[i]["--color=".len()..]) {
                Some(w) => color_when = w,
                None => {
                    eprintln!(
                        "nkg: bad --color {:?}: expected auto|always|never|ansi",
                        raw[i]
                    );
                    usage();
                }
            }
        } else if raw[i] == "--port" {
            i += 1;
            if i >= raw.len() {
                usage();
            }
            port = raw[i].parse().ok();
            if port.is_none() {
                eprintln!("nkg: bad --port {:?}: expected a port number", raw[i]);
                usage();
            }
        } else if raw[i].starts_with("--port=") {
            match raw[i]["--port=".len()..].parse::<u16>() {
                Ok(p) => port = Some(p),
                Err(_) => {
                    eprintln!("nkg: bad --port {:?}: expected a port number", raw[i]);
                    usage();
                }
            }
        } else if raw[i] == "-m" || raw[i] == "--max-count" {
            // Per-file match cap (rg: matching lines per file; -c prints the
            // capped counts). 0 is legal (matches nothing, exit 1).
            i += 1;
            if i >= raw.len() {
                usage();
            }
            match raw[i].parse::<usize>() {
                Ok(n) => max_count = Some(n),
                Err(_) => {
                    eprintln!("nkg: bad --max-count {:?}: expected a number", raw[i]);
                    usage();
                }
            }
        } else if raw[i].starts_with("--max-count=") {
            match raw[i]["--max-count=".len()..].parse::<usize>() {
                Ok(n) => max_count = Some(n),
                Err(_) => {
                    eprintln!("nkg: bad --max-count {:?}: expected a number", raw[i]);
                    usage();
                }
            }
        } else if raw[i].starts_with("-m") && !raw[i].starts_with("--") && raw[i].len() > 2 {
            // Attached short (`-m2`).
            match raw[i][2..].parse::<usize>() {
                Ok(n) => max_count = Some(n),
                Err(_) => {
                    eprintln!("nkg: bad -m {:?}: expected a number", raw[i]);
                    usage();
                }
            }
        } else if raw[i] == "-e" || raw[i] == "--regexp" {
            // Repeatable search pattern (OR); values take the next arg
            // verbatim. Any -e/-f makes every positional a path.
            i += 1;
            if i >= raw.len() {
                usage();
            }
            explicit_patterns = true;
            patterns_e.push(raw[i].clone());
        } else if raw[i].starts_with("--regexp=") {
            explicit_patterns = true;
            patterns_e.push(raw[i]["--regexp=".len()..].to_string());
        } else if raw[i] == "-f" || raw[i] == "--file" {
            // Repeatable pattern file (one pattern per line, `-` = stdin).
            i += 1;
            if i >= raw.len() {
                usage();
            }
            explicit_patterns = true;
            pattern_files.push(raw[i].clone());
        } else if raw[i].starts_with("--file=") {
            explicit_patterns = true;
            pattern_files.push(raw[i]["--file=".len()..].to_string());
        } else if raw[i] == "-F" || raw[i] == "--fixed-strings" {
            fixed_strings = true;
        } else if raw[i] == "-v" || raw[i] == "--invert-match" {
            invert_match = true;
        } else if raw[i] == "-w" || raw[i] == "--word-regexp" {
            word_regexp = true;
        } else if raw[i] == "--stats" {
            STATS.store(true, std::sync::atomic::Ordering::Relaxed);
        } else if raw[i] == "-x"
            || raw[i] == "--line-regexp"
            || raw[i] == "-P"
            || raw[i] == "--pcre2"
            || raw[i] == "-E"
            || raw[i] == "--encoding"
            || raw[i] == "-G"
        {
            // Parked matcher flags: loud exit 2, never a positional pattern.
            // (`--no-pcre2`/`--no-encoding` below are silent no-ops: the
            // default engine already satisfies them.)
            eprintln!("nkg: {} is not supported", raw[i]);
            usage();
        } else if raw[i] == "--no-pcre2" || raw[i] == "--no-encoding" {
            // No-op: requests the default engine/byte behavior we already do.
        } else if raw[i] == "-i" || raw[i] == "--ignore-case" {
            ignore_case = true;
        } else if raw[i] == "-q" || raw[i] == "--quiet" || raw[i] == "--silent" {
            quiet = true;
        } else if raw[i] == "-c" || raw[i] == "--count" {
            count_mode = true;
        } else if raw[i] == "-l" || raw[i] == "--files-with-matches" {
            files_only = true;
        } else if raw[i] == "--hidden" || raw[i] == "-." {
            walk_hidden = true;
        } else if raw[i] == "--no-hidden" {
            walk_hidden = false;
        } else if raw[i] == "--no-ignore" {
            walk_no_ignore = true;
        } else if raw[i] == "-L" || raw[i] == "--follow" {
            walk_follow = true;
        } else if raw[i] == "--no-follow" {
            walk_follow = false;
        } else if raw[i] == "-g" || raw[i] == "--glob" {
            i += 1;
            if i >= raw.len() {
                usage();
            }
            walk_globs.push(raw[i].clone());
        } else if raw[i].starts_with("--glob=") {
            walk_globs.push(raw[i]["--glob=".len()..].to_string());
        } else if raw[i].starts_with("-g") && !raw[i].starts_with("--") && raw[i].len() > 2 {
            // Attached short (`-g*.rs`), mirroring clap's short-value join.
            walk_globs.push(raw[i][2..].to_string());
        } else if raw[i] == "-d" || raw[i] == "--max-depth" {
            i += 1;
            if i >= raw.len() {
                usage();
            }
            match raw[i].parse::<usize>() {
                Ok(d) => walk_max_depth = Some(d),
                Err(_) => {
                    eprintln!("nkg: bad --max-depth {:?}: expected a number", raw[i]);
                    usage();
                }
            }
        } else if raw[i].starts_with("--max-depth=") {
            match raw[i]["--max-depth=".len()..].parse::<usize>() {
                Ok(d) => walk_max_depth = Some(d),
                Err(_) => {
                    eprintln!("nkg: bad --max-depth {:?}: expected a number", raw[i]);
                    usage();
                }
            }
        } else if raw[i].starts_with("-d") && !raw[i].starts_with("--") && raw[i].len() > 2 {
            // Attached short (`-d2`).
            match raw[i][2..].parse::<usize>() {
                Ok(d) => walk_max_depth = Some(d),
                Err(_) => {
                    eprintln!("nkg: bad -d {:?}: expected a number", raw[i]);
                    usage();
                }
            }
        } else if raw[i] == "--max-filesize" {
            i += 1;
            if i >= raw.len() {
                usage();
            }
            match parse_filesize(&raw[i]) {
                Some(n) => walk_max_filesize = Some(n),
                None => refuse_bad_filesize(&raw[i]),
            }
        } else if raw[i].starts_with("--max-filesize=") {
            match parse_filesize(&raw[i]["--max-filesize=".len()..]) {
                Some(n) => walk_max_filesize = Some(n),
                None => refuse_bad_filesize(&raw[i]),
            }
        } else if raw[i] == "-A" || raw[i] == "--after-context" {
            i += 1;
            if i >= raw.len() {
                usage();
            }
            match raw[i].parse::<usize>() {
                Ok(n) => ctx_a = Some(n),
                Err(_) => {
                    eprintln!("nkg: bad -A {:?}: expected a number", raw[i]);
                    usage();
                }
            }
        } else if raw[i] == "-B" || raw[i] == "--before-context" {
            i += 1;
            if i >= raw.len() {
                usage();
            }
            match raw[i].parse::<usize>() {
                Ok(n) => ctx_b = Some(n),
                Err(_) => {
                    eprintln!("nkg: bad -B {:?}: expected a number", raw[i]);
                    usage();
                }
            }
        } else if raw[i] == "-C" || raw[i] == "--context" {
            i += 1;
            if i >= raw.len() {
                usage();
            }
            match raw[i].parse::<usize>() {
                Ok(n) => ctx_c = Some(n),
                Err(_) => {
                    eprintln!("nkg: bad -C {:?}: expected a number", raw[i]);
                    usage();
                }
            }
        } else if raw[i].starts_with("--after-context=") {
            match raw[i]["--after-context=".len()..].parse::<usize>() {
                Ok(n) => ctx_a = Some(n),
                Err(_) => {
                    eprintln!("nkg: bad --after-context {:?}: expected a number", raw[i]);
                    usage();
                }
            }
        } else if raw[i].starts_with("--before-context=") {
            match raw[i]["--before-context=".len()..].parse::<usize>() {
                Ok(n) => ctx_b = Some(n),
                Err(_) => {
                    eprintln!("nkg: bad --before-context {:?}: expected a number", raw[i]);
                    usage();
                }
            }
        } else if raw[i].starts_with("--context=") {
            match raw[i]["--context=".len()..].parse::<usize>() {
                Ok(n) => ctx_c = Some(n),
                Err(_) => {
                    eprintln!("nkg: bad --context {:?}: expected a number", raw[i]);
                    usage();
                }
            }
        } else if raw[i] == "--group-separator" {
            i += 1;
            if i >= raw.len() {
                usage();
            }
            group_sep = raw[i].clone();
        } else if raw[i].starts_with("--group-separator=") {
            group_sep = raw[i]["--group-separator=".len()..].to_string();
        } else if raw[i].starts_with("-A") && !raw[i].starts_with("--") && raw[i].len() > 2 {
            // Attached short (`-A2`), mirroring the `-d2`/`-g` convention.
            // A non-numeric tail (e.g. a `-Apple` pattern) is a usage error,
            // matching rg (`-A` consumes the next arg as its number).
            match raw[i][2..].parse::<usize>() {
                Ok(n) => ctx_a = Some(n),
                Err(_) => {
                    eprintln!("nkg: bad -A {:?}: expected a number", raw[i]);
                    usage();
                }
            }
        } else if raw[i].starts_with("-B") && !raw[i].starts_with("--") && raw[i].len() > 2 {
            // Attached short (`-B2`).
            match raw[i][2..].parse::<usize>() {
                Ok(n) => ctx_b = Some(n),
                Err(_) => {
                    eprintln!("nkg: bad -B {:?}: expected a number", raw[i]);
                    usage();
                }
            }
        } else if raw[i].starts_with("-C") && !raw[i].starts_with("--") && raw[i].len() > 2 {
            // Attached short (`-C1`).
            match raw[i][2..].parse::<usize>() {
                Ok(n) => ctx_c = Some(n),
                Err(_) => {
                    eprintln!("nkg: bad -C {:?}: expected a number", raw[i]);
                    usage();
                }
            }
        } else if raw[i].len() > 1
            && raw[i].starts_with('-')
            && !raw[i].starts_with("--")
            && raw[i][1..]
                .chars()
                .all(|c| matches!(c, 'i' | 'q' | 'c' | 'l' | 'F' | 'v' | 'w'))
        {
            // Combined no-arg shorts (-cl, -iq, -iv, -vw, ...): claimed only
            // when EVERY char is a known no-arg short. Anything with other
            // letters falls through to positional — the shared short-cluster
            // protocol (FlagsCLS/FlagsAQ consented to this unified arm;
            // behavior for -c/-l/-cl/-lc/-cc and -i/-q/-iq/-qi is unchanged).
            // Bare `-` (stdin) never reaches here via the len>1 guard.
            for c in raw[i][1..].chars() {
                match c {
                    'i' => ignore_case = true,
                    'q' => quiet = true,
                    'c' => count_mode = true,
                    'l' => files_only = true,
                    'F' => fixed_strings = true,
                    'v' => invert_match = true,
                    'w' => word_regexp = true,
                    // Unreachable by the guard above; empty keeps the match
                    // exhaustive without a behavior claim.
                    _ => {}
                }
            }
        } else {
            pos.push(raw[i].clone());
        }
        i += 1;
    }
    // MatchFlags patterns: with any -e/-f every positional is a path (rg
    // shape; more than one path stays a usage error — single-root index).
    // Without -e/-f the first positional is the pattern, as before.
    if explicit_patterns {
        if pos.len() > 1 {
            usage();
        }
    } else if pos.is_empty() || pos.len() > 2 {
        usage();
    }
    // `-f` files load here (after usage checks, before dispatch): each line
    // a pattern, interior empties kept (match-all, probed on rg 15.1.0),
    // `-` reads piped stdin once. A missing file exits 2 with `nkg: msg`.
    let mut patterns: Vec<String> = patterns_e;
    if !pattern_files.is_empty() {
        let mut stdin_pats: Option<Vec<u8>> = None;
        for f in &pattern_files {
            let data: Vec<u8> = if f == "-" {
                if stdin_pats.is_none() {
                    let mut b = Vec::new();
                    use std::io::Read;
                    if std::io::stdin().read_to_end(&mut b).is_err() {
                        eprintln!("nkg: stdin: read error");
                        std::process::exit(2);
                    }
                    stdin_pats = Some(b);
                }
                stdin_pats.as_ref().unwrap().clone()
            } else {
                match std::fs::read(f) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("nkg: {f}: {e}");
                        std::process::exit(2);
                    }
                }
            };
            patterns.extend(split_pattern_lines(&data));
        }
    }
    if explicit_patterns && patterns.is_empty() {
        // `-f` with zero patterns (e.g. an empty file): rg matches nothing.
        // A never-matching regex keeps the whole pipeline (and exit 1)
        // uniform: `\b\B` is contradictory at one position (verified empty
        // against rg 15.1.0 semantics), compiles without look-around, and
        // holds no trigrams (full scan, like any gram-less pattern). Fixed
        // is cleared since this is a regex by construction.
        patterns.push("\\b\\B".to_string());
        fixed_strings = false;
    }
    if !explicit_patterns {
        patterns.push(pos[0].clone());
    }
    // Stdin search unit (FlagsCLS): an explicit `-` operand, or piped stdin
    // with no path operand, searches stdin as one unit labeled
    // `(standard input)` instead of walking the tree. A terminal with no
    // path defaults to root `.` (rg parity); piped stdin with no path keeps
    // the stdin unit. With -e/-f there is no pattern positional, so the
    // path shifts to pos[0] (or none when piped/terminal-default).
    let stdin_is_term = std::io::stdin().is_terminal();
    let stdin_explicit = if explicit_patterns {
        pos.first().map(|s| s.as_str()) == Some("-")
    } else {
        pos.get(1).map(|s| s.as_str()) == Some("-")
    };
    let stdin_piped = if explicit_patterns {
        pos.is_empty() && !stdin_is_term
    } else {
        pos.len() == 1 && !stdin_is_term
    };
    // Terminal bare (no path, stdin is a tty): search `.` like rg. Piped
    // stdin with no path stays the stdin unit via `stdin_piped` above.
    let terminal_root = stdin_is_term
        && (if explicit_patterns {
            pos.is_empty()
        } else {
            pos.len() == 1
        });
    if (stdin_explicit || stdin_piped) && port.is_some() {
        eprintln!("nkg: stdin search cannot use --port");
        usage();
    }
    if port.is_none()
        && explicit_patterns
        && pos.len() != 1
        && !stdin_explicit
        && !stdin_piped
        && !terminal_root
    {
        usage();
    }
    if port.is_none()
        && !explicit_patterns
        && pos.len() != 2
        && !stdin_explicit
        && !stdin_piped
        && !terminal_root
    {
        usage();
    }
    let stdin_mode = port.is_none() && (stdin_explicit || stdin_piped);
    let pattern = combine_patterns(&patterns, fixed_strings);
    let fixed_single = fixed_strings && patterns.len() == 1;
    let root = if explicit_patterns {
        PathBuf::from(pos.first().map(|s| s.as_str()).unwrap_or("."))
    } else {
        PathBuf::from(pos.get(1).map(|s| s.as_str()).unwrap_or("."))
    };
    // Traversal filters thread into every cold walk below; the index build
    // keeps defaults (full corpus) so gate A holds by construction.
    let walk_opts = WalkOptions {
        hidden: walk_hidden,
        no_ignore: walk_no_ignore,
        follow: walk_follow,
        max_depth: walk_max_depth,
        max_filesize: walk_max_filesize,
        globs: walk_globs,
    };
    // Color resolves once: text render only (JSON/-c/-l/-q never consult it).
    // Short-circuit keeps the default path off the is_terminal syscall.
    let color_on = format_text && color_enabled(color_when);
    // Context resolves once: an explicit -A/-B beats -C per side (rg 15.1.0
    // probe); `ctx_on` gates every context path below — when false the JSON,
    // text, and wire paths are byte-identical to before.
    let ctx_after = ctx_a.or(ctx_c).unwrap_or(0);
    let ctx_before = ctx_b.or(ctx_c).unwrap_or(0);
    let ctx_on = ctx_after > 0 || ctx_before > 0;
    // MatchFlags spec: the serve wire and the cold path share it (patterns
    // for grams/bonus, flags for matcher/verify/cap).
    // Subtree roots for serve: canonicalized absolute (daemon cwd may
    // differ) plus the raw operand for cold-shape display. Unresolvable
    // roots send a sentinel matching nothing (exit 1, not whole-tree).
    let root_raw = root.to_string_lossy().into_owned();
    let qroot_canon = std::fs::canonicalize(&root)
        .map(|c| c.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "\u{0}unresolvable".to_string());
    let mspec = MatchSpec {
        patterns: &patterns,
        fixed: fixed_strings,
        word: word_regexp,
        invert: invert_match,
        max_count,
        qroot: &qroot_canon,
        display_root: &root_raw,
    };

    let t0 = Instant::now();
    let mut ph = QueryPhases::new();
    // Root check runs before the serve-first probe so both paths agree on
    // exit status; subtree queries skip serve (the daemon covers the whole
    // index root) and go cold, where candidates are narrowed to the subtree.
    let walk_default = !walk_opts.hidden
        && !walk_opts.no_ignore
        && !walk_opts.follow
        && walk_opts.max_depth.is_none()
        && walk_opts.max_filesize.is_none()
        && walk_opts.globs.is_empty();
    let serve_ok = if port.is_none() && !stdin_mode && walk_default {
        if let Some(idx_path) = &use_index {
            serve_eligible_root(idx_path, &root)
        } else {
            false
        }
    } else {
        false
    };
    // Serve query state, resolved once for both serve entry points: the
    // request fields, how a classified row is retained, the client-side
    // highlight matcher, and the flags the response tail renders with.
    // `-q` is an aggregate shape — it prints nothing, and the `done` line
    // still supplies the diagnostics' totals.
    let sq = ServeQuery {
        pattern: &pattern,
        top,
        ignore_case,
        mspec: &mspec,
        mode: serve_mode(quiet, count_mode, files_only, ctx_on, format_text),
        // Color resolves once per query for the text render only.
        matcher: color_on
            .then(|| build_matcher_opts(&pattern, ignore_case, word_regexp, fixed_single).ok())
            .flatten(),
        group_sep: &group_sep,
        ctx_before,
        ctx_after,
        count_mode,
        files_only,
        quiet,
    };
    if port.is_none() && serve_ok {
        let idx_path = use_index.as_ref().expect("guarded by serve_ok");
        match try_serve_query(idx_path, &sq) {
            ServeProbe::Hit(rows) => {
                finish_serve_response(&rows, &sq, t0);
                return;
            }
            ServeProbe::MissWarn(msg) => {
                eprintln!("{msg}");
            }
            ServeProbe::MissSilent => {}
        }
    }
    if port.is_some() && !walk_default {
        eprintln!("nkg: walk filters set; bypassing server, searching locally");
    }
    if let Some(p) = port.filter(|_| walk_default) {
        let rows = client_query(p, &sq);
        if ctx_on && !rows.ctx_echo {
            // Old daemon ignored the context fields: matches render without
            // carried context (the serve-first path fails over to cold
            // instead — no cold tree exists for an explicit --port).
            eprintln!("nkg: server ignored context flags (old daemon?)");
        }
        finish_serve_response(&rows, &sq, t0);
        return;
    }

    let matcher = match build_matcher_opts(&pattern, ignore_case, word_regexp, fixed_single) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("nkg: bad regex: {e}");
            std::process::exit(2);
        }
    };
    // ST-5 columnar cold path: borrow-banked FileHits (pid = file id when
    // indexed, ptab index on scan) + flattened side scores vec + pid-indexed
    // escaped paths. Serve emits the same banked path; the check pins both
    // byte-identical.
    // `-l`/`-q` need one path per file and discard the rows, so the searcher
    // can stop at each file's first match. `-m n` is NOT safe here: it caps
    // matches before ranking, and a file's score comes from how many matches it
    // banked, so capping early changes which files rank highest. `-m` stays the
    // post-pass in `apply_max_count`.
    let match_limit = files_only.then_some(1u64);
    let mut hits: Vec<FileHits> = vec![];

    let mut walk_error = false;
    // Request-scoped I/O-error latch for this query (see handle_client).
    let verify_latch = AtomicBool::new(false);
    let mut ptab: Vec<String> = vec![];
    let mut hits_indexed = false;
    let files: usize;
    let mut load_ms = 0u128;
    let idx_opt: Option<Index> = if stdin_mode {
        // Stdin bypasses the index entirely: the piped bytes are not indexed
        // content. --use-index is ignored, not an error.
        None
    } else if let Some(idx_path) = &use_index {
        let t_load = Instant::now();
        let idx = load_index_for_query(idx_path, &root);
        // One clock read for both consumers. `as_millis` stays exact here --
        // deriving it from a float would truncate differently on some inputs.
        let load = t_load.elapsed();
        load_ms = load.as_millis();
        ph.load = load.as_secs_f64() * 1e3;
        Some(idx)
    } else {
        None
    };
    if stdin_mode {
        // No walk, no index: stdin bytes are the only search unit, labeled
        // `(standard input)`. The shared sort/emit tail below applies
        // unchanged (--top truncates, -c/-l aggregate, JSON stays default).
        files = 1;
        ptab = vec![STDIN_LABEL.to_string()];
        let mut input = Vec::new();
        {
            use std::io::Read;
            if std::io::stdin().read_to_end(&mut input).is_err() {
                eprintln!("nkg: stdin: read error");
                std::process::exit(2);
            }
        }
        // Frozen-wrapper default (same contract as the daemon): plain stdin
        // queries run the frozen entry; invert goes direct. Zero behavior
        // change — the wrapper is exactly _inv(false).
        let stdin_hit = if invert_match {
            search_stdin_raw_inv(&input, &matcher, true)
        } else {
            search_stdin_raw(&input, &matcher)
        };
        if quiet {
            // Existence only, mirroring the file branches: no stdout, 0/1 exit.
            quiet_exit(stdin_hit.is_some(), files, load_ms, t0, false);
        }
        hits = stdin_hit.map(|h| vec![h]).unwrap_or_default();
        // `-m` caps the unit before rank/top/count/emit, like files below.
        apply_max_count(&mut hits, max_count);
        if ctx_on {
            // The stdin buffer outlives verify (FlagsCLS coupling): attach
            // line tables over it so stdin renders context like files.
            for fh in hits.iter_mut() {
                attach_context(fh, &input);
            }
        }
    } else if let Some(idx) = &idx_opt {
        let mut scores = vec![0.0f64; idx.files.len()];
        let mut order: Vec<u32> = vec![];
        // `-i` forces the scan fallback: trigram postings are raw bytes, so
        // case-sensitive grams would false-negative on case variants
        // (`hello` grams miss `HELLO` files). Scanning makes indexed==scan
        // hold by construction; the matcher itself folds case. `-v` forces
        // it too: inverted matches live outside the gram files.
        // `--hidden`/`--no-ignore`/`-L` force it as well: the index is built
        // with walk defaults (hidden skipped, ignores respected, links
        // unfollowed), so those files are absent from postings — no candidate
        // filter could recover them. The fallback walks with live walk_opts,
        // so indexed==scan holds by construction there too. Shrink-only
        // filters (-d/-g/--max-filesize) stay on the fast path: candidates
        // are intersected pre-verify below.
        let mut fallback =
            ignore_case || invert_match || walk_hidden || walk_no_ignore || walk_follow;
        match if fallback {
            None
        } else {
            query_grams_multi(&patterns, fixed_strings)
        } {
            None => fallback = true,
            Some(ors) => {
                // Shared rank core: intersect/union/idf, any-pattern path
                // bonus (single-pattern = contains(pattern), as before),
                // depth penalty, descending order + per-file scores.
                let t_rank = Instant::now();
                let (o, s) = rank_ors(idx, &ors, &|p| {
                    patterns.iter().any(|pat| p.contains(pat.as_str()))
                });
                ph.rank = t_rank.elapsed().as_secs_f64() * 1e3;
                order = o;
                scores = s;
            }
        }
        if fallback {
            eprintln!("nkg: no usable literal, falling back to scan");
            let t_walk = Instant::now();
            let (paths, had_walk_error) = walk_files(&root, &walk_opts);
            ph.walk += t_walk.elapsed().as_secs_f64() * 1e3;
            walk_error |= had_walk_error;
            files = paths.len();
            ptab = paths
                .iter()
                .map(|p| strip_dot_slash(&p.to_string_lossy()).to_owned())
                .collect();
            if quiet {
                // Existence only: `find_any` stops the parallel wave at the
                // first banked hit instead of verifying every file.
                let found = (0u32..ptab.len() as u32)
                    .into_par_iter()
                    .find_any(|pid| {
                        verify_one_raw_ctx(VerifyInput {
                            err: &verify_latch,
                            pid: *pid,
                            path: &ptab[*pid as usize],
                            matcher: &matcher,
                            file_score: 0.0,
                            before: ctx_before,
                            after: ctx_after,
                            invert: invert_match,
                            follow: walk_follow,
                            match_limit,
                        })
                        .is_some()
                    })
                    .is_some();
                quiet_exit(
                    found,
                    files,
                    load_ms,
                    t0,
                    walk_error | take_verify_io_error(&verify_latch),
                );
            }
            let t_ver = Instant::now();
            hits = (0u32..ptab.len() as u32)
                .into_par_iter()
                .filter_map(|pid| {
                    // Same per-file score as the scan branch below (path bonus
                    // minus depth): the fallback is a scan, so its rows must
                    // be byte-identical to one, not just set-equal.
                    let ps = &ptab[pid as usize];
                    // `Path::new` rather than `PathBuf::from`: the owned
                    // buffer was allocated per candidate purely to count
                    // components, which borrows do just as well.
                    let depth = std::path::Path::new(ps).components().count() as f64;
                    let bonus = if patterns.iter().any(|pat| ps.contains(pat.as_str())) {
                        100.0
                    } else {
                        0.0
                    };
                    verify_one_raw_ctx(VerifyInput {
                        err: &verify_latch,
                        pid,
                        path: ps,
                        matcher: &matcher,
                        file_score: bonus - depth,
                        before: ctx_before,
                        after: ctx_after,
                        invert: invert_match,
                        follow: walk_follow,
                        match_limit,
                    })
                })
                .collect();
            ph.verify += t_ver.elapsed().as_secs_f64() * 1e3;
        } else {
            // Shrink-only traversal filters apply to candidates pre-verify,
            // not to the index itself (the build keeps full-corpus defaults
            // so gate A holds). The rank candidates are intersected with a
            // live `walk_files` set — the same walker the scan branches use,
            // so depth/size/glob semantics match by construction. Defaults
            // skip the walk entirely: zero behavior or output change on the
            // hot path. (Expand filters never reach here: --hidden,
            // --no-ignore, and -L take the scan fallback above.)
            if walk_opts.max_depth.is_some()
                || walk_opts.max_filesize.is_some()
                || !walk_opts.globs.is_empty()
            {
                let t_walk = Instant::now();
                let (walked, had_walk_error) = walk_files(&root, &walk_opts);
                ph.walk += t_walk.elapsed().as_secs_f64() * 1e3;
                walk_error |= had_walk_error;
                let allowed: HashSet<String> = walked
                    .into_iter()
                    .map(|p| strip_dot_slash(&p.to_string_lossy()).to_owned())
                    .collect();
                order.retain(|id| allowed.contains(&idx.files[*id as usize]));
            }
            files = order.len();
            if quiet {
                // Existence only over the pruned candidate set: same
                // `find_any` short-circuit as the scan branches.
                let found = order
                    .par_iter()
                    .find_any(|id| {
                        verify_one_raw(
                            &verify_latch,
                            **id,
                            &idx.files[**id as usize],
                            &matcher,
                            scores[**id as usize],
                            walk_follow,
                            Some(1), // -q needs existence only
                        )
                        .is_some()
                    })
                    .is_some();
                quiet_exit(
                    found,
                    files,
                    load_ms,
                    t0,
                    walk_error | take_verify_io_error(&verify_latch),
                );
            }
            // Rank-ordered parallel verify, kth early exit between batches
            // (spec §6: match score ≤ file score, exit moves only with proof).
            let t_ver = Instant::now();
            hits = verify_batched(&order, &scores, top, true, |id| {
                verify_one_raw_ctx(VerifyInput {
                    err: &verify_latch,
                    pid: id,
                    path: &idx.files[id as usize],
                    matcher: &matcher,
                    file_score: scores[id as usize],
                    before: ctx_before,
                    after: ctx_after,
                    invert: false,
                    follow: walk_follow,
                    match_limit,
                })
            });
            ph.verify += t_ver.elapsed().as_secs_f64() * 1e3;
            hits_indexed = true;
        }
    } else {
        let t_walk = Instant::now();
        let (paths, had_walk_error) = walk_files(&root, &walk_opts);
        ph.walk += t_walk.elapsed().as_secs_f64() * 1e3;
        walk_error |= had_walk_error;
        files = paths.len();
        ptab = paths
            .iter()
            .map(|p| strip_dot_slash(&p.to_string_lossy()).to_owned())
            .collect();
        if quiet {
            // Existence only: `find_any` stops the parallel wave at the
            // first banked hit instead of verifying every file.
            let found = (0u32..ptab.len() as u32)
                .into_par_iter()
                .find_any(|pid| {
                    verify_one_raw_ctx(VerifyInput {
                        err: &verify_latch,
                        pid: *pid,
                        path: &ptab[*pid as usize],
                        matcher: &matcher,
                        file_score: 0.0,
                        before: ctx_before,
                        after: ctx_after,
                        invert: invert_match,
                        follow: walk_follow,
                        match_limit: None,
                    })
                    .is_some()
                })
                .is_some();
            quiet_exit(
                found,
                files,
                load_ms,
                t0,
                walk_error | take_verify_io_error(&verify_latch),
            );
        }
        let t_ver = Instant::now();
        hits = (0u32..ptab.len() as u32)
            .into_par_iter()
            .filter_map(|pid| {
                // Same verify core as the indexed path: depth folds into
                // file_score, so scores match the old inline Collector.
                let ps = &ptab[pid as usize];
                let depth = std::path::Path::new(ps).components().count() as f64;
                let bonus = if patterns.iter().any(|pat| ps.contains(pat.as_str())) {
                    100.0
                } else {
                    0.0
                };
                verify_one_raw_ctx(VerifyInput {
                    err: &verify_latch,
                    pid,
                    path: ps,
                    matcher: &matcher,
                    file_score: bonus - depth,
                    before: ctx_before,
                    after: ctx_after,
                    invert: invert_match,
                    follow: walk_follow,
                    match_limit,
                })
            })
            .collect();
        ph.verify += t_ver.elapsed().as_secs_f64() * 1e3;
    }
    // `-m`: per-file cap before rank/top/count/emit. Truncation precedes
    // context derivation (agreed with ContextLines): context renders from
    // surviving metas. No `-m` = no-op.
    let t_sort = Instant::now();
    apply_max_count(&mut hits, max_count);
    // Columnar sort: flattened side scores vec drives index order; comparator
    // verbatim the fat-Hit one, so rank (ties included) is unchanged.
    // `loc` maps each flat position to (file, meta) for banked decode.
    let (hit_scores, loc) = flat_scores(&hits);
    let mut ord = raw_order(&hit_scores);
    if let Some(n) = top {
        ord.truncate(n);
    }
    ph.sort = t_sort.elapsed().as_secs_f64() * 1e3;
    ph.tail = Instant::now();
    ph.rows = ord.len() as u64;
    let matches = ord.len();
    // Audit #8: `F` counts distinct hit files, not files walked/candidates.
    // SHAPE CHANGE: `-c` single-file hits and `-m1` now report `in 1 files`
    // instead of `in N files` (walked count).
    let matched = matched_file_count(&ord, &loc);
    // Display state for the three renderers below (context, text, JSON).
    let src = EmitSource {
        hits: &hits,
        loc: &loc,
        idx_opt: &idx_opt,
        ptab: &ptab,
        hits_indexed,
        color_on,
        matcher: &matcher,
    };
    if count_mode || files_only {
        // `-c` / `-l` cold emit: per-file surviving-hit (post---top) counts,
        // path-sorted for a stable contract (rg emits walk-parallel order).
        // `-l` wins over `-c`; `-q` never reaches here (quiet_exit above).
        // Zero-count files are omitted (see write_aggregates).
        let mut counts: HashMap<usize, usize> = HashMap::new();
        for &i in &ord {
            let (fi, _) = loc[i as usize];
            *counts.entry(hits[fi as usize].pid as usize).or_default() += 1;
        }
        let mut rows: Vec<(&str, usize)> = counts
            .iter()
            .map(|(&pid, &n)| (path_of(&idx_opt, &ptab, hits_indexed, pid), n))
            .collect();
        rows.sort_by(|a, b| a.0.cmp(b.0));
        let stdout = std::io::stdout();
        let mut writer = std::io::BufWriter::with_capacity(1024 * 1024, stdout.lock());
        write_aggregates(&mut writer, &rows, files_only);
        stdout_flush(&mut writer);
        ph.report();
        eprintln!(
            "nkg: {matches} matches in {matched} files, {} ms (index load {load_ms} ms)",
            t0.elapsed().as_millis()
        );
        walk_error |= take_verify_io_error(&verify_latch);
        if walk_error {
            std::process::exit(2);
        }
        if matches == 0 {
            std::process::exit(1);
        }
        return;
    }
    if ctx_on {
        // Context render: rank by hit, context attached. The ranked `ord`
        // (post---top, so context never consumes rank budget) folds into
        // per-file groups in first-seen rank order; lines ascend within a
        // file; windows expand by before/after, merge on overlap/adjacency;
        // `--` (or `--group-separator`) parts disjoint in-file groups, never
        // across files — the rg 15.1.0 shape probe. A line with several hits
        // renders once; `matches` (hits, multiplicity intact) drives the
        // diagnostics and the 0/1 exit, like `-c`.
        let groups = ctx_file_groups(&hits, &loc, &ord);
        let est: usize = groups
            .iter()
            .map(|(fi, mis)| ctx_group_bytes(&hits[*fi], mis, ctx_before, ctx_after, FRAME_TEXT))
            .sum();
        let parts: Vec<Vec<u8>> = match emit_plan(groups.len(), est) {
            None => vec![render_ctx_chunk(
                &src, &groups, ctx_before, ctx_after, &group_sep,
            )],
            Some(n) => groups
                .par_chunks(n)
                .map(|c| render_ctx_chunk(&src, c, ctx_before, ctx_after, &group_sep))
                .collect(),
        };
        let stdout = std::io::stdout();
        let mut writer = std::io::BufWriter::with_capacity(1024 * 1024, stdout.lock());
        for part in &parts {
            stdout_write_all(&mut writer, part);
        }
        stdout_flush(&mut writer);
        ph.report();
        eprintln!(
            "nkg: {matches} matches in {matched} files, {} ms (index load {load_ms} ms)",
            t0.elapsed().as_millis()
        );
        walk_error |= take_verify_io_error(&verify_latch);
        if walk_error {
            std::process::exit(2);
        }
        if matches == 0 {
            std::process::exit(1);
        }
        return;
    }
    if format_text {
        // Text emit: same ranked `ord` as JSON (rank order preserved — same
        // hits, same order, different rendering), no score, line numbers
        // always on. Skips the JSON path-escape table; -c/-l/-q returned
        // above. ContextLines' context>0 renderer takes over when context
        // flags are set (plain text here is the no-context trigger).
        // Same chunked-parallel shape as the JSON emitter: text mode renders
        // strictly less per row than JSON (no escape table, no score) yet was
        // emitting single-threaded, so on a heavy query it cost more than the
        // JSON path it should have been cheaper than.
        let est = est_output_bytes(&ord, &hits, &loc, FRAME_TEXT);
        let parts: Vec<Vec<u8>> = match emit_plan(ord.len(), est) {
            None => vec![render_text_chunk(&src, &ord)],
            Some(n) => ord
                .par_chunks(n)
                .map(|c| render_text_chunk(&src, c))
                .collect(),
        };
        let stdout = std::io::stdout();
        let mut writer = std::io::BufWriter::with_capacity(1024 * 1024, stdout.lock());
        for part in &parts {
            stdout_write_all(&mut writer, part);
        }
        stdout_flush(&mut writer);
        ph.report();
        eprintln!(
            "nkg: {matches} matches in {matched} files, {} ms (index load {load_ms} ms)",
            t0.elapsed().as_millis()
        );
        walk_error |= take_verify_io_error(&verify_latch);
        if walk_error {
            std::process::exit(2);
        }
        if matches == 0 {
            std::process::exit(1);
        }
        return;
    }
    // Ordered parallel emission (cold emission only): manual memchr escaper
    // into chunk buffers per-thread, join in order, single sequential write.
    // Serial fallback under threshold keeps selective/small queries off the
    // rayon ramp. serde_json remains the differential check in tests.
    // Each unique path is escaped once per query (heavy-full emits 51k hits
    // from ~3k files) into a pid-indexed table: no per-hit HashMap, no Arc.
    // Indexed pids address the index file table, scan pids the ptab.
    // Hit text decodes from the file arena at emit (`banked_text`): valid
    // UTF-8 borrows, so the common path allocates nothing per hit.
    let table_len = match &idx_opt {
        Some(idx) if hits_indexed => idx.files.len(),
        _ => ptab.len(),
    };
    let mut esc: Vec<Option<Vec<u8>>> = vec![None; table_len];
    for &i in &ord {
        let (fi, _) = loc[i as usize];
        let pid = hits[fi as usize].pid as usize;
        if esc[pid].is_none() {
            let ps: &str = path_of(&idx_opt, &ptab, hits_indexed, pid);
            let mut v = Vec::with_capacity(ps.len() + 2);
            push_escaped_json(&mut v, ps);
            esc[pid] = Some(v);
        }
    }
    // Emit one line per ordered hit; sequential and chunked-parallel share
    // this body so both stay byte-identical.
    let stdout = std::io::stdout();
    let mut writer = std::io::BufWriter::with_capacity(1024 * 1024, stdout.lock());
    let est = est_output_bytes(&ord, &hits, &loc, FRAME_JSON);
    let parts: Vec<Vec<u8>> = match emit_plan(ord.len(), est) {
        None => vec![render_json_chunk(&src, &esc, &ord)],
        Some(n) => ord
            .par_chunks(n)
            .map(|c| render_json_chunk(&src, &esc, c))
            .collect(),
    };
    for part in &parts {
        stdout_write_all(&mut writer, part);
    }
    stdout_flush(&mut writer);
    ph.report();
    eprintln!(
        "nkg: {matches} matches in {matched} files, {} ms (index load {load_ms} ms)",
        t0.elapsed().as_millis()
    );
    walk_error |= take_verify_io_error(&verify_latch);
    if walk_error {
        std::process::exit(2);
    }
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
        // Runs of four or more now yield four-grams, so the proxy for "this
        // branch kept its literal" is a four-gram of `needle_1`.
        assert!(
            got[0].contains(
                &(((b'n' as u32) << 24)
                    | ((b'e' as u32) << 16)
                    | ((b'e' as u32) << 8)
                    | (b'd' as u32))
            ),
            "{got:?}"
        );
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
        let dir = std::env::temp_dir().join(format!("nkg_cached_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.txt");
        std::fs::write(&a, "needle here\nsecond needle\n").unwrap();
        let ap = a.to_string_lossy().into_owned();
        let matcher = RegexMatcher::new("needle").unwrap();
        let fdc = FdCache::new(1);
        let latch = AtomicBool::new(false);
        let plain =
            verify_one_raw(&latch, 0, &ap, &matcher, 10.0, false, None).expect("plain must hit");
        let cached = verify_one_raw_cached(&latch, 0, &ap, &matcher, 10.0, Some((&fdc, 0)), false)
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
    fn group_and_repeat_falls_back() {
        // `(?` (flags, named groups, comments, lookaround) and `{n}`
        // repetition can drop a required trigram: full scan.
        assert!(query_grams("(?i)needle_alpha").is_none());
        assert!(query_grams("(?P<word>NEEDLE_ALPHA)").is_none());
        assert!(query_grams("(?#comment)NEEDLE_ALPHA").is_none());
        assert!(query_grams("NEEDLE_[A-Z]{2,}").is_none());
        assert!(query_grams("confi{1,}g").is_none());
        // Escaped or class-contained `(?` / `{d` stay literal: indexable.
        assert!(query_grams("[(?]needle_alpha").is_some());
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
        let mut packed: Vec<u32> = trips.iter().map(gram_pack).collect();
        packed.sort();
        assert_eq!(packed, trips.iter().map(gram_pack).collect::<Vec<_>>());
    }
    #[test]
    fn top_zero_indexed_matches_scan_empty() {
        let dir = std::env::temp_dir().join(format!("nkg_top0_{}", std::process::id()));
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
            postings: Postings::default(),
        };
        let matcher = RegexMatcher::new("needle_haystack_content").unwrap();
        let order = vec![0u32, 1u32];
        let scores = vec![10.0f64, 5.0f64];
        let latch = AtomicBool::new(false);
        let batched = verify_batched(&order, &scores, Some(0), false, |id| {
            verify_one_raw_ctx(VerifyInput {
                err: &latch,
                pid: id,
                path: &idx.files[id as usize],
                matcher: &matcher,
                file_score: scores[id as usize],
                before: 0,
                after: 0,
                invert: false,
                follow: false,
                match_limit: None,
            })
        });
        // Columnar flat scan (serve semantics): full verify, rank over side
        // scores, top-0 truncate.
        let scanned_all: Vec<FileHits> = [(0u32, 10.0f64), (1u32, 5.0f64)]
            .into_iter()
            .filter_map(|(id, s)| {
                verify_one_raw_cached(
                    &latch,
                    id,
                    &idx.files[id as usize],
                    &matcher,
                    s,
                    None,
                    false,
                )
            })
            .collect();
        let (scanned_scores, _) = flat_scores(&scanned_all);
        let mut scanned_ord = raw_order(&scanned_scores);
        scanned_ord.clear();
        assert!(batched.is_empty(), "top=0 batched must return 0 hits");
        assert!(scanned_ord.is_empty(), "top=0 scan must return 0 hits");
        assert!(!scanned_all.is_empty(), "fixture must match without top");
        std::fs::remove_dir_all(&dir).ok();
    }
    #[test]
    fn matchflags_combine_scopes_groups() {
        let one = |s: &str| s.to_string();
        // Single non-fixed passes through verbatim (default path identical).
        assert_eq!(combine_patterns(&[one("a|b")], false), "a|b");
        // Wrapping keeps (?i) scoped and inner | from merging branches.
        assert_eq!(
            combine_patterns(&[one("(?i)foo"), one("BAR")], false),
            "(?:(?i)foo)|(?:BAR)"
        );
        assert_eq!(
            combine_patterns(&[one("(a|b)"), one("c")], false),
            "(?:(a|b))|(?:c)"
        );
        // Fixed pre-escapes so separators stay regex alternation.
        assert_eq!(
            combine_patterns(&[one("a.c"), one("x|y")], true),
            "(?:a\\.c)|(?:x\\|y)"
        );
        assert_eq!(combine_patterns(&[one("a.c")], true), "a.c");
    }

    #[test]
    fn matchflags_grams_multi() {
        let one = |s: &str| s.to_string();
        // Single non-fixed delegates exactly.
        assert_eq!(
            query_grams_multi(&[one("NEEDLE_ALPHA")], false),
            query_grams("NEEDLE_ALPHA")
        );
        // Fixed uses literal windows, even where regex parse would bail.
        let g = query_grams_multi(&[one("foo*bar")], true).unwrap();
        assert_eq!(g.len(), 1);
        assert!(g[0].contains(&gram_pack(b"foo")));
        assert!(g[0].contains(&gram_pack(b"bar")));
        // Multi unions branches; any gram-less pattern forces a full scan.
        let u = query_grams_multi(&[one("NEEDLE_ALPHA"), one("needle_1")], false).unwrap();
        assert_eq!(u.len(), 2);
        assert!(query_grams_multi(&[one("NEEDLE_ALPHA"), one("a|b")], false).is_none());
        // Empty/short fixed patterns hold no trigram: full scan (an empty
        // pattern matches every line, so pruning would false-negative).
        assert!(query_grams_multi(&[one("")], true).is_none());
        assert!(query_grams_multi(&[one("ab")], true).is_none());
    }

    #[test]
    fn matchflags_pattern_lines() {
        let v = |b: &[u8]| split_pattern_lines(b);
        assert!(v(b"").is_empty());
        assert_eq!(v(b"a\n"), vec!["a"]);
        // Interior empties kept (match-all); trailing artifact dropped.
        assert_eq!(v(b"a\n\nb\n"), vec!["a", "", "b"]);
        assert_eq!(v(b"\n"), vec![""]);
        assert_eq!(v(b"a\r\nb\r\n"), vec!["a", "b"]);
        assert_eq!(v(b"a\rb"), vec!["a\rb"]);
    }

    #[test]
    fn matchflags_matcher_word_fixed() {
        // Word bounds via the searcher core (rg 15.1.0 shapes: foo-bar yes,
        // foobar/foo_bar no).
        let w = build_matcher_opts("foo", false, true, false).unwrap();
        for (line, want) in [
            ("a foo b", 1),
            ("foobar", 0),
            ("foo_bar", 0),
            ("foo-bar", 1),
            ("foo", 1),
        ] {
            let mut s = grep_searcher::SearcherBuilder::new().build();
            let mut sink = ColCollector {
                arena: vec![],
                metas: vec![],
                path_bonus: 0.0,
                match_limit: None,
            };
            s.search_slice(&w, line.as_bytes(), &mut sink).unwrap();
            assert_eq!(sink.metas.len(), want, "word line {line:?}");
        }
        // Fixed treats metachars literally.
        let f = build_matcher_opts("a.c", false, false, true).unwrap();
        let mut s = grep_searcher::SearcherBuilder::new().build();
        let mut sink = ColCollector {
            arena: vec![],
            metas: vec![],
            path_bonus: 0.0,
            match_limit: None,
        };
        s.search_slice(&f, b"a.c axc", &mut sink).unwrap();
        assert_eq!(sink.metas.len(), 1);
        assert_eq!(sink.arena, b"a.c axc");
    }

    #[test]
    fn matchflags_invert_and_max_count() {
        let dir = std::env::temp_dir().join(format!("nkg_matchflags_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.txt");
        std::fs::write(&a, "foo one\nbar two\nfoo three\nbaz four\n").unwrap();
        let ap = a.to_string_lossy().into_owned();
        let m = RegexMatcher::new("foo").unwrap();
        let latch = AtomicBool::new(false);
        let norm = verify_one_raw_ctx(VerifyInput {
            err: &latch,
            pid: 0,
            path: &ap,
            matcher: &m,
            file_score: 0.0,
            before: 0,
            after: 0,
            invert: false,
            follow: false,
            match_limit: None,
        })
        .expect("plain must hit");
        assert_eq!(norm.metas.len(), 2);
        let inv = verify_one_raw_ctx(VerifyInput {
            err: &latch,
            pid: 0,
            path: &ap,
            matcher: &m,
            file_score: 0.0,
            before: 0,
            after: 0,
            invert: true,
            follow: false,
            match_limit: None,
        })
        .expect("invert must hit");
        assert_eq!(inv.metas.len(), 2);
        assert_eq!((inv.metas[0].line, inv.metas[1].line), (2, 4));
        assert_eq!(banked_text(&inv, &inv.metas[0]), "bar two");
        // Same through the cached twin (serve path).
        let inv_c = verify_one_raw_cached_ctx(CachedVerify {
            err: &latch,
            pid: 0,
            path: &ap,
            matcher: &m,
            file_score: 0.0,
            before: 0,
            after: 0,
            fdc: None,
            invert: true,
            follow: false,
        })
        .expect("cached invert");
        assert_eq!(inv_c.metas.len(), 2);
        assert_eq!(inv_c.metas[0].line, 2);
        // -m keeps file order (first m).
        let mut capped = verify_one_raw_ctx(VerifyInput {
            err: &latch,
            pid: 0,
            path: &ap,
            matcher: &m,
            file_score: 0.0,
            before: 0,
            after: 0,
            invert: false,
            follow: false,
            match_limit: None,
        })
        .unwrap();
        apply_max_count(std::slice::from_mut(&mut capped), Some(1));
        assert_eq!(capped.metas.len(), 1);
        assert_eq!(capped.metas[0].line, 1);
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
        let mut p = Vec::with_capacity(h.path.len() + 2);
        push_escaped_json(&mut p, &h.path);
        emit_raw_with_path(&mut m, &p, h.line, &h.text, h.score);
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
        // `path`: the differential check over actual emission bytes.
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

#[cfg(test)]
mod color_tests {
    use super::*;

    fn lit(pat: &str) -> RegexMatcher {
        build_matcher(pat, false).unwrap()
    }

    #[test]
    fn parse_when_values() {
        assert_eq!(parse_color_when("auto"), Some(ColorWhen::Auto));
        assert_eq!(parse_color_when("always"), Some(ColorWhen::Always));
        assert_eq!(parse_color_when("never"), Some(ColorWhen::Never));
        assert_eq!(parse_color_when("ansi"), Some(ColorWhen::Always));
        assert_eq!(parse_color_when("bogus"), None);
        assert_eq!(parse_color_when(""), None);
        assert_eq!(parse_color_when("Always"), None);
    }

    #[test]
    fn enabled_explicit_wins() {
        assert!(color_enabled(ColorWhen::Always));
        assert!(!color_enabled(ColorWhen::Never));
        // Auto follows the TTY only — no assert (environment-dependent).
    }

    #[test]
    fn span_wrap_matches_rg_bytes() {
        // Exact SGR sequence byte-probed on rg 15.1.0 (`--color=always`).
        let m = lit("hello");
        assert_eq!(
            &*colorize_spans("hello world", &m),
            "\x1b[0m\x1b[1m\x1b[31mhello\x1b[0m world"
        );
    }

    #[test]
    fn no_match_borrows_back_verbatim() {
        let m = lit("zzz");
        let out = colorize_spans("hello world", &m);
        assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
        assert_eq!(&*out, "hello world");
    }

    #[test]
    fn zero_width_spans_skipped() {
        // `x*` matches empty everywhere: must emit no codes at all.
        let m = lit("x*");
        let out = colorize_spans("ab", &m);
        assert_eq!(&*out, "ab");
        assert!(!out.bytes().any(|b| b == 0x1b));
    }

    #[test]
    fn multi_span_all_wrapped() {
        let m = lit("o");
        assert_eq!(
            &*colorize_spans("foo boo", &m),
            "f\x1b[0m\x1b[1m\x1b[31mo\x1b[0m\x1b[0m\x1b[1m\x1b[31mo\x1b[0m b\x1b[0m\x1b[1m\x1b[31mo\x1b[0m\x1b[0m\x1b[1m\x1b[31mo\x1b[0m"
        );
    }

    #[test]
    fn colored_row_delegates_framing() {
        // Plain and colored rows share `path:line:` framing; only the text
        // span differs.
        let m = lit("needle");
        let mut plain = Vec::new();
        let mut colored = Vec::new();
        emit_text_row(&mut plain, "a.txt", 7, "a needle here");
        emit_text_row_colored(&mut colored, "a.txt", 7, "a needle here", &m);
        assert_eq!(&plain, b"a.txt:7:a needle here\n");
        assert_eq!(
            &colored,
            b"a.txt:7:a \x1b[0m\x1b[1m\x1b[31mneedle\x1b[0m here\n"
        );
    }

    #[test]
    fn serve_colored_mirrors_plain_shape() {
        // Same rows, same order through the streamed text renderer; only
        // spans wrapped.
        let raw = b"{\"path\":\"a.txt\",\"line\":1,\"text\":\"hi needle\"}\n\
                    {\"path\":\"b.txt\",\"line\":2,\"text\":\"no hit here\"}\n";
        let m = lit("needle");
        let plain = render_buffered_text(raw, None);
        let colored = render_buffered_text(raw, Some(&m));
        assert_eq!(&plain, b"a.txt:1:hi needle\nb.txt:2:no hit here\n");
        assert_eq!(
            &colored,
            b"a.txt:1:hi \x1b[0m\x1b[1m\x1b[31mneedle\x1b[0m\nb.txt:2:no hit here\n"
        );
    }
}

#[cfg(test)]
mod context_tests {
    use super::*;

    #[test]
    fn groups_merge_overlap_and_adjacency() {
        // Overlap: [1,3]+[3,5] -> one group. Adjacency ([2,4]+[5,7]) merges
        // with no separator — probed on rg 15.1.0.
        assert_eq!(compute_groups(&[2, 4], 1, 1), vec![(1, 5)]);
        assert_eq!(compute_groups(&[3, 7], 1, 1), vec![(2, 4), (6, 8)]);
    }
    #[test]
    fn groups_clamp_top_and_split() {
        // Line 1 with before=2 clamps at 1; far-apart windows stay split.
        assert_eq!(compute_groups(&[1], 2, 1), vec![(1, 2)]);
        assert_eq!(compute_groups(&[1, 8], 1, 1), vec![(1, 2), (7, 9)]);
        // Empty input, empty output; zero context is the line itself.
        assert!(compute_groups(&[], 2, 2).is_empty());
        assert_eq!(compute_groups(&[5], 0, 0), vec![(5, 5)]);
    }

    #[test]
    fn attach_remap_is_byte_identical() {
        // attach_context must not change decoded hit text: metas remapped
        // into the full-file arena decode exactly what the match-banked
        // arena decoded (CRLF + missing-trailing-newline included). A CRLF
        // line keeps its `\r` on both sides — probed byte-for-byte on rg
        // 15.1.0, which renders `1-first\r` for this exact file.
        let dir = std::env::temp_dir().join(format!("nkg_ctx_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("a.txt");
        std::fs::write(&f, "first\r\nneedle one\nmiddle\nneedle two").unwrap();
        let fp = f.to_string_lossy().into_owned();
        let matcher = RegexMatcher::new("needle").unwrap();
        let latch = AtomicBool::new(false);
        let plain = verify_one_raw(&latch, 0, &fp, &matcher, 10.0, false, None).expect("must hit");
        let before: Vec<String> = plain
            .metas
            .iter()
            .map(|m| banked_text(&plain, m).into_owned())
            .collect();
        let attached = verify_one_raw_ctx(VerifyInput {
            err: &latch,
            pid: 0,
            path: &fp,
            matcher: &matcher,
            file_score: 10.0,
            before: 1,
            after: 1,
            invert: false,
            follow: false,
            match_limit: None,
        })
        .expect("must hit");
        assert_eq!(attached.line_starts.len(), 4);
        for (m, b) in attached.metas.iter().zip(before.iter()) {
            assert_eq!(&banked_text(&attached, m).into_owned(), b);
        }
        // Context lines decode through the same table.
        assert_eq!(ctx_line_text(&attached, 1), "first\r");
        assert_eq!(ctx_line_text(&attached, 3), "middle");
        assert_eq!(ctx_line_text(&attached, 4), "needle two");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn served_context_renders_rg_shape() {
        // Hits + carried ctx lines regroup into rg-shaped rows with `--`
        // only between disjoint in-file groups, never across files.
        let raw = b"{\"path\":\"b.txt\",\"line\":2,\"text\":\"hit B\",\"score\":1.0}\n\
                    {\"path\":\"b.txt\",\"line\":1,\"text\":\"ctx B\",\"score\":1.0,\"ctx\":true}\n\
                    {\"path\":\"a.txt\",\"line\":1,\"text\":\"hit A1\",\"score\":0.0}\n\
                    {\"path\":\"a.txt\",\"line\":9,\"text\":\"hit A2\",\"score\":0.0}\n";
        let out = render_served_context(raw, 1, 1, "--", None);
        assert_eq!(
            &out,
            b"b.txt:1-ctx B\nb.txt:2:hit B\na.txt:1:hit A1\n--\na.txt:9:hit A2\n"
        );
        // Empty separator prints no separator lines.
        let out = render_served_context(raw, 1, 1, "", None);
        assert_eq!(
            &out,
            b"b.txt:1-ctx B\nb.txt:2:hit B\na.txt:1:hit A1\na.txt:9:hit A2\n"
        );
    }
}

#[cfg(test)]
mod git_skip_tests {
    use super::*;

    fn plant(root: &std::path::Path) {
        // Fake `.git` tree with pack files, a hidden file, and a normal
        // file: mirrors the live `rg --hidden` / `--no-ignore` probes.
        std::fs::create_dir_all(root.join(".git/objects/pack")).unwrap();
        std::fs::write(root.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(root.join(".git/objects/pack/t.pack"), "packbytes\n").unwrap();
        std::fs::write(root.join(".hidden.txt"), "hidden\n").unwrap();
        std::fs::write(root.join("normal.txt"), "normal\n").unwrap();
    }

    fn names(root: &PathBuf, opts: &WalkOptions) -> std::collections::HashSet<String> {
        walk_files(root, opts)
            .0
            .into_iter()
            .map(|p| {
                p.strip_prefix(root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    fn opts(hidden: bool, no_ignore: bool) -> WalkOptions {
        WalkOptions {
            hidden,
            no_ignore,
            follow: false,
            max_depth: None,
            max_filesize: None,
            globs: vec![],
        }
    }

    #[test]
    fn git_four_contexts_match_rg() {
        // Probed rg 15.1.0 on this repo: default/hidden/no-ignore all skip
        // `.git`; only --hidden+--no-ignore descends it.
        let dir = std::env::temp_dir().join(format!("nkg_gitskip_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        plant(&dir);
        let root = dir.clone();
        let has_git =
            |s: &std::collections::HashSet<String>| s.iter().any(|p| p.starts_with(".git"));
        // Default: gate A + byte-identical gate — exactly the visible file.
        let d = names(&root, &opts(false, false));
        assert_eq!(
            d,
            std::collections::HashSet::from(["normal.txt".to_string()])
        );
        // --hidden alone: hidden files appear, `.git` still skipped.
        let h = names(&root, &opts(true, false));
        assert!(h.contains("normal.txt"), "{h:?}");
        assert!(h.contains(".hidden.txt"), "{h:?}");
        assert!(!has_git(&h), "--hidden must not descend .git: {h:?}");
        // --no-ignore alone: hidden filter still skips `.git`.
        let n = names(&root, &opts(false, true));
        assert!(!has_git(&n), "--no-ignore alone keeps hidden skip: {n:?}");
        // --hidden+--no-ignore: `.git` contents (incl. pack) searched.
        let b = names(&root, &opts(true, true));
        assert!(b.contains(".git/HEAD"), "{b:?}");
        assert!(
            b.iter().any(|p| p.starts_with(".git/objects/pack/")),
            "{b:?}"
        );
        assert!(b.contains(".hidden.txt"), "{b:?}");
        assert!(b.contains("normal.txt"), "{b:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn git_explicit_operand_still_searches() {
        // Probed rg: `rg --hidden pat .git` searches the explicit dir.
        let dir = std::env::temp_dir().join(format!("nkg_gitroot_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        std::fs::write(dir.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        let git_root = dir.join(".git");
        let s = names(&git_root, &opts(true, false));
        assert!(s.contains("HEAD"), "{s:?}");
        std::fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
mod varint_tests {
    use super::{get_varint, put_varint};

    #[test]
    fn varint_round_trips() {
        for v in [0u32, 1, 127, 128, 300, 65_535, 1 << 20, u32::MAX] {
            let mut b = Vec::new();
            put_varint(&mut b, v);
            let (got, next) = get_varint(&b, 0).expect("decodes");
            assert_eq!(got, v, "round trip for {v}");
            assert_eq!(next, b.len());
        }
    }

    #[test]
    fn varint_rejects_wider_than_u32() {
        // Five continuation bytes. Accumulating in u32 yields exactly
        // 0xFFFFFFFF, which is not `> u32::MAX`, so it would slip through as
        // Some — proving the early return exists, though that value alone would
        // still be refused downstream by the `id < nfiles` bound.
        let b = [0xffu8, 0xff, 0xff, 0xff, 0x7f, 0];
        assert!(
            get_varint(&b, 0).is_none(),
            "must refuse a value wider than u32"
        );
    }

    #[test]
    fn varint_would_not_silently_decode_to_an_in_range_id() {
        // The actual hazard, not just a missed early return: `0x10 << 28`
        // lands on bit 32, so a u32 accumulator drops it and this decodes to
        // id 1 — in range for any real tree, i.e. a corrupt index quietly
        // yielding a wrong match instead of a refusal. The true value is
        // 4294967297, which the u64 accumulator rejects.
        let b = [0x81u8, 0x80, 0x80, 0x80, 0x10, 0];
        assert_eq!(
            get_varint(&b, 0),
            None,
            "a wide varint must never decode to a small in-range id"
        );
        let mut u32acc: u32 = 0;
        for (i, byte) in [0x81u8, 0x80, 0x80, 0x80, 0x10].iter().enumerate() {
            u32acc |= u32::from(byte & 0x7f) << (7 * i);
        }
        assert_eq!(u32acc, 1, "the u32 form really does decode to id 1");
    }

    #[test]
    fn varint_rejects_run_past_end() {
        assert!(get_varint(&[0x80u8], 0).is_none(), "continuation past end");
        assert!(get_varint(&[], 0).is_none(), "empty buffer");
    }
}

#[cfg(test)]
mod serve_wire_tests {
    use super::*;

    /// A served response as the daemon writes it: hits in rank order, the
    /// `done` line last. `text` on the hit row carries an escaped
    /// `"ctx":true` inside it — the exact shape a substring test would
    /// misclassify as context.
    const RESPONSE: &[u8] = b"{\"path\":\"a.txt\",\"line\":1,\"text\":\"saw \\\"ctx\\\":true here\",\"score\":0.5}\n\
                              {\"path\":\"b.txt\",\"line\":2,\"text\":\"carried ctx\",\"score\":0.5,\"ctx\":true}\n\
                              {\"path\":\"a.txt\",\"line\":3,\"text\":\"second hit\",\"score\":0.5}\n\
                              {\"done\":true,\"ms\":1.0,\"ctx\":true}\n";

    fn read(mode: ServeMode) -> (ServeRows, Vec<u8>) {
        let mut cursor = RESPONSE;
        let mut out = vec![];
        let rows =
            read_serve_response(&mut cursor, mode, None, &mut out).expect("complete response");
        (rows, out)
    }

    #[test]
    fn ctx_marker_in_match_text_counts_as_a_hit() {
        // `"ctx":true` is the LAST field of a carried context row, so the
        // same sequence inside a match's own text cannot classify as
        // context. Two hits (a.txt twice), one carried context row, and the
        // marker-bearing text is rendered as text, not dropped.
        let (rows, out) = read(ServeMode::Text);
        assert_eq!(rows.matches, 2, "ctx marker inside text must not eat a hit");
        assert_eq!(rows.matched(), 1, "only a.txt is a hit file");
        assert_eq!(rows.files.get(b"a.txt".as_slice()), Some(&2));
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "a.txt:1:saw \"ctx\":true here\na.txt:3:second hit\n"
        );
        assert!(rows.done && rows.ctx_echo);
    }

    #[test]
    fn context_mode_collects_hits_and_carried_rows() {
        // Context regroups the whole response, so it is the one mode that
        // keeps the wire: nothing reaches stdout until the stream ends.
        let (rows, out) = read(ServeMode::Context);
        assert_eq!(rows.matches, 2);
        assert!(out.is_empty(), "context rows never reach stdout early");
        let collected = String::from_utf8(rows.buf).unwrap();
        assert_eq!(collected.matches('\n').count(), 3, "hits + the carried row");
        assert!(collected.contains(r#","ctx":true}"#));
        assert!(
            !collected.contains(r#"{"done""#),
            "the done line is not regrouped"
        );
    }

    #[test]
    fn json_mode_passes_the_wire_through_verbatim() {
        // Default JSON: hit rows reach stdout byte-for-byte, in wire order,
        // and the carried context row never does.
        let (rows, out) = read(ServeMode::Json);
        assert_eq!(rows.matches, 2);
        assert!(rows.emitted);
        let seen = String::from_utf8(out).unwrap();
        assert_eq!(seen.matches('\n').count(), 2);
        assert!(seen.starts_with(r#"{"path":"a.txt","line":1,"#));
        assert!(!seen.contains(r#""ctx":true"#));
        assert!(!seen.contains(r#"{"done""#));
    }

    #[test]
    fn scan_survives_adversarial_match_text() {
        // A path with escaped quote/backslash, and text carrying a quote, a
        // backslash and a literal `{"path":"` — all past fields the scan
        // stops at, so none of it can be reached.
        let wire =
            br#"{"path":"a\"b\\c.txt","line":7,"text":"q\"r\\s {\"path\":\"z\"}","score":1.0}"#;
        let row = scan_wire_row(wire).expect("complete row");
        assert_eq!(row.path, br#"a\"b\\c.txt"#);
        assert_eq!(row.line, 7);
        assert_eq!(row.text, br#"q\"r\\s {\"path\":\"z\"}"#);
        // Truncated, foreign or trailing-garbage rows degrade to None.
        assert!(scan_wire_row(br#"{"path":"a.txt","line":1,"text":"trunc"#).is_none());
        assert!(scan_wire_row(b"not a wire row").is_none());
        assert!(scan_wire_row(br#"{"path":"a.txt","line":x,"text":"y","score":1}"#).is_none());
        assert!(scan_wire_row(br#"{"path":"a.txt","line":1,"text":"y","score":1} junk"#).is_none());
    }

    #[test]
    fn unescape_is_the_inverse_of_the_wire_escaper() {
        for s in [
            "plain",
            "a\"b",
            "a\\b",
            "a\nb\tc\rd",
            "\u{1}\u{8}\u{c}\u{1f}",
            "{\"path\":\"x\"}",
            "\"ctx\":true",
            "trailing backslash \\",
        ] {
            let mut enc = vec![];
            push_escaped_json(&mut enc, s);
            let mut dec = vec![];
            push_unescaped_json(&mut dec, &enc);
            assert_eq!(String::from_utf8(dec).unwrap(), s, "round trip for {s:?}");
        }
    }

    #[test]
    fn truncated_and_foreign_rows_degrade_not_panic() {
        let wire = b"{\"path\":\"a.txt\",\"line\":1,\"text\":\"trunc\n\
                    not a wire row\n\
                    {\"path\":\"a.txt\",\"line\":4,\"text\":\"ok\",\"score\":1.0}\n\
                    {\"done\":true}\n";
        let mut cursor = &wire[..];
        let mut out = vec![];
        let rows = read_serve_response(&mut cursor, ServeMode::Text, None, &mut out).expect("done");
        // Unparseable rows still count as rows (the wire contract is one
        // object per line) but render nothing and add no file count.
        assert_eq!(rows.matches, 3);
        assert_eq!(rows.matched(), 1);
        assert_eq!(String::from_utf8(out).unwrap(), "a.txt:4:ok\n");
    }

    /// Records every `write_all` as its own batch, so a test can see exactly
    /// where the daemon's batch boundaries fell on the wire.
    #[derive(Default)]
    struct BatchLog(Vec<Vec<u8>>);

    impl Write for BatchLog {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.push(b.to_vec());
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn emit_batches_break_only_between_rows() {
        // The streamed response carries one invariant: a batch may leave the
        // socket only BETWEEN rows, because the client frames on newlines and
        // `emit_raw_with_path` appends exactly one newline-terminated row.
        // Drives far more rows than one 64 KiB batch holds, checks every batch
        // ends on a row boundary, and checks the shipped bytes equal the
        // single-buffer render byte for byte.
        const ROWS: u64 = 20_000;
        let mut want: Vec<u8> = vec![];
        for line in 0..ROWS {
            emit_raw_with_path(&mut want, b"a/b.txt", line + 1, "payload text", 1.5);
        }
        assert!(
            want.len() > SERVE_EMIT_BYTES * 4,
            "fixture must span several batches"
        );

        let mut log = BatchLog::default();
        let mut buf: Vec<u8> = Vec::with_capacity(SERVE_EMIT_BYTES);
        let mut broken = false;
        for line in 0..ROWS {
            serve_emit_line(&mut log, &mut buf, &mut broken, |b| {
                emit_raw_with_path(b, b"a/b.txt", line + 1, "payload text", 1.5)
            });
        }
        assert!(!broken, "a Vec sink never breaks");
        let tail = std::mem::take(&mut buf);
        assert!(
            log.0.len() >= 10,
            "rows must span many batches: {}",
            log.0.len()
        );
        for b in &log.0 {
            assert!(b.ends_with(b"\n"), "batch ends mid-row: {b:?}");
        }
        let got: Vec<u8> = log.0.concat().into_iter().chain(tail).collect();
        assert_eq!(got, want, "streamed bytes differ from the buffered render");
    }

    #[test]
    fn emit_batch_failure_latches_broken() {
        // A refused write is latched once and never retried: the emit loops
        // stop on it, so a stalled reader cannot spend the write timeout once
        // per remaining batch.
        struct Dead;
        impl Write for Dead {
            fn write(&mut self, _b: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut buf: Vec<u8> = Vec::new();
        let mut broken = false;
        for line in 0..20_000u64 {
            serve_emit_line(&mut Dead, &mut buf, &mut broken, |b| {
                emit_raw_with_path(b, b"a/b.txt", line + 1, "payload text", 1.5)
            });
            if broken {
                break; // what the emit loops do
            }
        }
        assert!(broken, "a refused write must latch broken");
        assert!(
            buf.len() <= SERVE_EMIT_BYTES + 256,
            "the batch is cleared after shipping, so a dead socket cannot \
             spend the write timeout once per remaining batch"
        );
    }
}

#[cfg(test)]
mod emit_tests {
    use super::*;

    /// Ranked banked hits: `files` files of `rows` hit lines, every line
    /// `row_bytes` long. Row text carries a quote and a backslash so the
    /// JSON escaper is on the path.
    struct Fix {
        hits: Vec<FileHits>,
        loc: Vec<(u32, u32)>,
        ord: Vec<u32>,
        ptab: Vec<String>,
        none: Option<Index>,
        matcher: RegexMatcher,
    }

    impl Fix {
        fn src(&self) -> EmitSource<'_> {
            EmitSource {
                hits: &self.hits,
                loc: &self.loc,
                idx_opt: &self.none,
                ptab: &self.ptab,
                hits_indexed: false,
                color_on: false,
                matcher: &self.matcher,
            }
        }
        /// Per-pid JSON path table, as the JSON arm builds it.
        fn esc(&self) -> Vec<Option<Vec<u8>>> {
            let mut esc: Vec<Option<Vec<u8>>> = vec![None; self.ptab.len()];
            for fh in self.hits.iter() {
                let mut v = Vec::new();
                push_escaped_json(&mut v, &self.ptab[fh.pid as usize]);
                esc[fh.pid as usize] = Some(v);
            }
            esc
        }
    }

    fn fix(files: usize, rows: usize, row_bytes: usize) -> Fix {
        let mut line = Vec::from(*b"needle \"q\" \\ pad ");
        while line.len() < row_bytes {
            line.extend_from_slice(b"padpadpad");
        }
        line.truncate(row_bytes);
        line.push(b'\n');
        let mut hits = Vec::with_capacity(files);
        let mut loc = Vec::with_capacity(files * rows);
        let mut ptab = Vec::with_capacity(files);
        for fi in 0..files {
            let mut fh = FileHits {
                pid: fi as u32,
                arena: vec![],
                metas: vec![],
                line_starts: vec![],
            };
            for r in 0..rows {
                let start = fh.arena.len() as u32;
                fh.arena.extend_from_slice(&line);
                fh.metas.push(HitMeta {
                    line: (r + 1) as u64 * 7,
                    start,
                    end: fh.arena.len() as u32,
                    score: 10.0 - r as f64,
                });
                loc.push((fi as u32, fh.metas.len() as u32 - 1));
            }
            ptab.push(format!("dir{fi}/file{fi}.txt"));
            hits.push(fh);
        }
        let ord: Vec<u32> = (0..loc.len() as u32).collect();
        Fix {
            hits,
            loc,
            ord,
            ptab,
            none: None,
            matcher: RegexMatcher::new("needle").unwrap(),
        }
    }

    fn join(parts: &[Vec<u8>]) -> Vec<u8> {
        parts.iter().flat_map(|p| p.iter().copied()).collect()
    }

    #[test]
    fn few_huge_rows_take_the_parallel_path() {
        // Few rows, enormous bytes: a row-count gate reads a small row count
        // and renders megabytes of text through one serial buffer, and a
        // 4096-row chunk hands all of it to a single worker.
        //
        // The fixture has to be big enough to fill the pool, because the
        // property under test is that the chunk size spreads across EVERY
        // worker. At a fixed 240 rows the assertion only held on machines
        // with few cores: 240 rows in ~18-row chunks is 14 chunks, so it
        // passed at 8 threads and failed at 32. Scale rows with the thread
        // count instead, with headroom over the ~18 rows a chunk holds.
        let threads = rayon::current_num_threads();
        let rows = (threads * 24).max(240);
        let f = fix(rows.div_ceil(60), 60, 56 * 1024);
        let est = est_output_bytes(&f.ord, &f.hits, &f.loc, FRAME_TEXT);
        let plan = emit_plan(f.ord.len(), est)
            .expect("byte-heavy, row-light output must render in parallel");
        assert!(
            f.ord.len().div_ceil(plan) >= rayon::current_num_threads(),
            "{plan}-row chunks over {} rows reaches fewer than {} workers",
            f.ord.len(),
            rayon::current_num_threads()
        );
    }

    #[test]
    fn a_chunk_reserves_the_bytes_it_renders() {
        // The failure this guards is UNDER-reservation: a 128 B/row reserve
        // against 56 KB rows under-reserves 440x, and the chunk then grows by
        // doubling through ~12 serial realloc+memcpy copies.
        //
        // Slack is proportional to chunk row count, not a fixed quantity, so
        // assert the ratio rather than a byte count. FRAME_TEXT=128 is
        // deliberately generous against a real ~38 B of path+line framing,
        // which makes over-reserve scale with rows: measured 26 KB on 240 rows
        // and 378 KB on 3,600. An absolute limit therefore encodes the size of
        // whatever fixture it was written against and says nothing about how
        // accurate the estimator is; it happened to hold here only because
        // EMIT_CHUNK_MAX_ROWS caps a chunk at 4,096 rows, which bounds slack at
        // 4096 x 90 B = 360 KB. If that cap were ever raised the old limit
        // would silently become wrong rather than failing.
        const MAX_OVER_RESERVE: f64 = 2.0;

        // Few, huge rows: the estimate is near-exact, so the reserve and the
        // final capacity should agree exactly. If the reserve were too small
        // the buffer would double and capacity would overshoot it.
        let f = fix(4, 60, 56 * 1024);
        let est = est_output_bytes(&f.ord, &f.hits, &f.loc, FRAME_TEXT);
        let out = render_text_chunk(&f.src(), &f.ord);
        assert!(
            out.capacity() <= est,
            "capacity {} overshot the {} B reserve: the buffer doubled",
            out.capacity(),
            est
        );
        let ratio = out.capacity() as f64 / out.len() as f64;
        assert!(
            ratio < MAX_OVER_RESERVE,
            "reserved {ratio:.2}x the output ({}/{} B) on few-huge rows",
            out.capacity(),
            out.len()
        );

        // Many short rows: framing dominates, so this is the shape where a
        // per-row constant actually accumulates, and the one the absolute
        // form of this assertion would have failed on.
        let many = fix(60, 60, 512);
        assert!(
            many.ord.len() >= 3_000,
            "fixture must be large enough for per-row slack to accumulate"
        );
        let big = render_text_chunk(&many.src(), &many.ord);
        assert!(
            big.capacity() >= big.len(),
            "reserved {} B for {} B of output on many-rows: the buffer had to grow",
            big.capacity(),
            big.len()
        );
        let ratio = big.capacity() as f64 / big.len() as f64;
        assert!(
            ratio < MAX_OVER_RESERVE,
            "reserved {ratio:.2}x the output ({}/{} B) over {} rows",
            big.capacity(),
            big.len(),
            many.ord.len()
        );
    }

    #[test]
    fn plan_reads_bytes_not_rows() {
        // 240 rows of 560 KB: one row per chunk, so the rows reach every
        // worker instead of one 4096-row chunk.
        let plan = emit_plan(240, 240 * 560 * 1024).expect("134 MB of output renders in parallel");
        assert!(240usize.div_ceil(plan) >= rayon::current_num_threads());
        // 51k short rows keep the row-capped chunking they have always had.
        assert_eq!(emit_plan(51_410, 51_410 * 160), Some(4096));
        // A few tens of kilobytes still renders into one serial buffer.
        assert_eq!(emit_plan(4000, 4096), None);
        assert_eq!(emit_plan(0, 0), None);
    }

    #[test]
    fn top_truncation_sizes_from_the_rows_that_print() {
        // `--top 5` over a file with 1.9 MB banked prints 5 rows: ~41 KB,
        // which stays serial. Sizing from the file arena instead would
        // report 1.9 MB and open the gate for a five-row answer.
        let f = fix(1, 240, 8 * 1024);
        let top: Vec<u32> = f.ord.iter().copied().take(5).collect();
        let est = est_output_bytes(&top, &f.hits, &f.loc, FRAME_TEXT);
        assert_eq!(emit_plan(top.len(), est), None);
        let banked: usize = f.hits.iter().map(|h| h.arena.len()).sum();
        assert!(
            est * 10 < banked,
            "estimate {est} must be a fraction of {banked}"
        );
    }

    #[test]
    fn chunking_never_changes_a_byte() {
        // Many short rows, and row counts either side of the old 4000-row
        // threshold, render identically through one serial buffer and
        // through any chunking.
        for (files, rows, row_bytes) in
            [(3usize, 1667usize, 40usize), (3, 1333, 100), (4, 1000, 100)]
        {
            let f = fix(files, rows, row_bytes);
            let est = est_output_bytes(&f.ord, &f.hits, &f.loc, FRAME_TEXT);
            let serial = render_text_chunk(&f.src(), &f.ord);
            for n in [
                1usize,
                7,
                emit_plan(f.ord.len(), est).unwrap_or(1),
                f.ord.len(),
            ] {
                let parts: Vec<Vec<u8>> = f
                    .ord
                    .par_chunks(n)
                    .map(|c| render_text_chunk(&f.src(), c))
                    .collect();
                assert_eq!(join(&parts), serial, "text {files}x{rows} rows, chunk {n}");
            }
            let esc = f.esc();
            let serial = render_json_chunk(&f.src(), &esc, &f.ord);
            for n in [
                1usize,
                7,
                emit_plan(f.ord.len(), est).unwrap_or(1),
                f.ord.len(),
            ] {
                let parts: Vec<Vec<u8>> = f
                    .ord
                    .par_chunks(n)
                    .map(|c| render_json_chunk(&f.src(), &esc, c))
                    .collect();
                assert_eq!(join(&parts), serial, "json {files}x{rows} rows, chunk {n}");
            }
        }
    }

    #[test]
    fn chunking_never_changes_a_byte_on_huge_rows() {
        let f = fix(4, 60, 56 * 1024);
        let est = est_output_bytes(&f.ord, &f.hits, &f.loc, FRAME_TEXT);
        let serial = render_text_chunk(&f.src(), &f.ord);
        for n in [1usize, 2, est / f.ord.len(), f.ord.len()] {
            let parts: Vec<Vec<u8>> = f
                .ord
                .par_chunks(n)
                .map(|c| render_text_chunk(&f.src(), c))
                .collect();
            assert_eq!(join(&parts), serial, "text, chunk {n}");
        }
        let esc = f.esc();
        let serial = render_json_chunk(&f.src(), &esc, &f.ord);
        for n in [1usize, 2, est / f.ord.len(), f.ord.len()] {
            let parts: Vec<Vec<u8>> = f
                .ord
                .par_chunks(n)
                .map(|c| render_json_chunk(&f.src(), &esc, c))
                .collect();
            assert_eq!(join(&parts), serial, "json, chunk {n}");
        }
    }

    #[test]
    fn ctx_chunking_never_changes_a_byte() {
        // Two files, two hit lines each, `-C1`: disjoint in-file groups
        // part on `--`, and grouping the files into any number of chunks
        // must not move a byte.
        let dir = std::env::temp_dir().join(format!("nkg_emit_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let body = "l1\nneedle a\nl3\nl4\nl5\nneedle b\nl7\n";
        let mut hits = vec![];
        let mut ptab = vec![];
        for fi in 0..2 {
            let f = dir.join(format!("f{fi}.txt"));
            std::fs::write(&f, body).unwrap();
            let fp = f.to_string_lossy().into_owned();
            ptab.push(fp.clone());
            let matcher = RegexMatcher::new("needle").unwrap();
            let latch = AtomicBool::new(false);
            hits.push(
                verify_one_raw_ctx(VerifyInput {
                    err: &latch,
                    pid: fi as u32,
                    path: &fp,
                    matcher: &matcher,
                    file_score: 10.0,
                    before: 1,
                    after: 1,
                    invert: false,
                    follow: false,
                    match_limit: None,
                })
                .expect("must hit"),
            );
        }
        let (scores, loc) = flat_scores(&hits);
        let ord = raw_order(&scores);
        let groups = ctx_file_groups(&hits, &loc, &ord);
        let none: Option<Index> = None;
        let matcher = RegexMatcher::new("needle").unwrap();
        let src = EmitSource {
            hits: &hits,
            loc: &loc,
            idx_opt: &none,
            ptab: &ptab,
            hits_indexed: false,
            color_on: false,
            matcher: &matcher,
        };
        let serial = render_ctx_chunk(&src, &groups, 1, 1, "--");
        let want = ptab
            .iter()
            .map(|p| {
                format!(
                    "{p}:1-l1\n{p}:2:needle a\n{p}:3-l3\n--\n{p}:5-l5\n{p}:6:needle b\n{p}:7-l7\n"
                )
            })
            .collect::<String>();
        assert_eq!(String::from_utf8_lossy(&serial), want);
        for n in [1usize, 2, groups.len()] {
            let parts: Vec<Vec<u8>> = groups
                .par_chunks(n)
                .map(|c| render_ctx_chunk(&src, c, 1, 1, "--"))
                .collect();
            assert_eq!(join(&parts), serial, "context groups, chunk {n}");
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
