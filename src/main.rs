use grep_regex::RegexMatcher;
use grep_searcher::Searcher;
use grep_searcher::{SearcherBuilder, Sink, SinkMatch};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, IsTerminal, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
mod cli;
mod matcher;
mod prefilter;
mod walk;
use cli::{
    color_enabled, colorize_spans, parse_color_when, print_help, print_version, usage, ColorWhen,
};
use matcher::{
    apply_max_count, build_matcher_opts, combine_patterns, grams_of, query_grams,
    query_grams_multi, split_pattern_lines, GramSet,
};
use walk::{
    canon_root, is_binary, parse_filesize, refuse_bad_filesize, root_cookie, strip_dot_slash,
    walk_files, WalkOptions,
};
#[derive(Serialize, Deserialize, Clone)]
#[cfg(test)]
struct Hit {
    path: std::sync::Arc<String>,
    line: u64,
    text: String,
    score: f64,
}

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
    line_starts: Vec<u32>,
}

struct ColCollector {
    arena: Vec<u8>,
    metas: Vec<HitMeta>,
    path_bonus: f64,
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
    match_limit: Option<u64>,
}

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
fn take_verify_io_error(err: &AtomicBool) -> bool {
    err.swap(false, Ordering::Relaxed)
}

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
    let ok = SEARCHER.with(|s| {
        BUF.with(|b| {
            let mut buf = b.borrow_mut();
            buf.clear();
            let mut local: Option<Searcher> = None;
            let mut normal = s.borrow_mut();
            if invert || match_limit.is_some() {
                let mut b = SearcherBuilder::new();
                if invert {
                    b.invert_match(true);
                }
                if let Some(limit) = match_limit {
                    b.max_matches(Some(limit));
                }
                local = Some(b.build());
            }
            let searcher: &mut Searcher = match local.as_mut() {
                Some(inv) => inv,
                None => &mut normal,
            };
            (|| -> std::io::Result<bool> {
                use std::io::{Read, Seek, SeekFrom};
                let mut f = open_verify_file(std::path::Path::new(path), follow)?;
                let mut head = [0u8; 8192];
                let n = f.read(&mut head)?;
                if n == 0 {
                    return Ok(true);
                }
                if memchr::memchr(0, &head[..n]).is_some() {
                    return Ok(true);
                }
                if before == 0 && after == 0 {
                    f.seek(SeekFrom::Start(0))?;
                    return Ok(searcher.search_reader(matcher, &mut f, &mut sink).is_ok());
                }
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
    let ok = SEARCHER.with(|s| {
        BUF.with(|b| {
            let mut buf = b.borrow_mut();
            buf.clear();
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
                if buf.is_empty() {
                    return Ok(true);
                }
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
            BUF.with(|b| attach_context(&mut fh, &b.borrow()));
        }
        Some(fh)
    } else {
        None
    }
}

enum Postings {
    Owned {
        keys: Vec<u32>,
        off: Vec<u32>,
        ids: Vec<u32>,
    },
    Raw {
        hdr: usize,
        npost: usize,
        data: std::sync::Arc<memmap2::Mmap>,
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
    fn npost(&self) -> usize {
        match self {
            Postings::Owned { keys, .. } => keys.len(),
            Postings::Raw { npost, .. } => *npost,
        }
    }
    fn key_at(&self, i: usize) -> u32 {
        match self {
            Postings::Owned { keys, .. } => keys[i],
            Postings::Raw { hdr, data, .. } => {
                let at = hdr + i * POSTING_HDR;
                u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
            }
        }
    }
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
    fn decode_run(data: &[u8], at: usize, blen: usize, nfiles: usize, out: &mut Vec<u32>) {
        out.clear();
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
    fn ids_in_range(&self, nfiles: usize) -> bool {
        match self {
            Postings::Owned { ids, .. } => ids.iter().all(|&id| (id as usize) < nfiles),
            Postings::Raw { npost, .. } => {
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

impl<'de> Deserialize<'de> for Postings {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_map(FlatPostingsVisitor)
    }
}

#[derive(Default)]
struct FlatBuild {
    entries: Vec<(u32, u32, u32)>,
    ids: Vec<u32>,
}

impl FlatBuild {
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
    root: String,
    root_dev: u64,
    root_ino: u64,
    files: Vec<String>,
    postings: Postings,
}

fn validate_stored_files(idx_path: &str, files: &[String]) {
    #[cfg(unix)]
    {
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

fn write_index_file(idx_path: &str, bytes: &[u8]) {
    if let Ok(m) = std::fs::symlink_metadata(idx_path) {
        if m.file_type().is_symlink() {
            eprintln!("nkg: refusing to write index through symlink {idx_path}");
            std::process::exit(2);
        }
    }
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

fn refuse_index(idx_path: &str, detail: &str, why: &dyn std::fmt::Display) -> ! {
    eprintln!("nkg: unreadable index {idx_path} ({detail}? rebuild with `nkg index`): {why}");
    std::process::exit(2);
}

fn refuse_stale_index(idx_path: &str) -> ! {
    let want = String::from_utf8_lossy(BIN_MAGIC);
    eprintln!("nkg: stale index format {idx_path} (expected {want}): rebuild with `nkg index`");
    std::process::exit(2);
}

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
const BIN_MAGIC: &[u8; 8] = b"NKGREP06";
const POSTING_HDR: usize = 16;

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
    let hdr = cur;
    let table_end = hdr.saturating_add(npost.saturating_mul(POSTING_HDR));
    if table_end > data.len() {
        refuse("truncated posting header table");
    }
    let mut prev = 0u32;
    let mut first = true;
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

const MAX_INDEX_BYTES: u64 = 4 * 1024 * 1024 * 1024;
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
    if len == 0 {
        eprintln!("nkg: unreadable index {idx_path} (empty): rebuild with `nkg index`");
        std::process::exit(2);
    }
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

fn read_index_header_bytes(idx_path: &str) -> Vec<u8> {
    use std::io::Read;
    let mut f = match std::fs::File::open(idx_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("nkg: cannot read index {idx_path}: {e}");
            std::process::exit(2);
        }
    };
    const FIXED: usize = 28;
    let mut d = vec![0u8; FIXED];
    if let Err(e) = f.read_exact(&mut d) {
        eprintln!("nkg: unreadable index {idx_path}: {e}");
        std::process::exit(2);
    }
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
    let mut remap: Vec<Option<u32>> = Vec::new();
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
    if !rel.as_os_str().is_empty() {
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
            if ids.len() != before {
                keys.push(*k);
                off.push(ids.len() as u32);
            }
        }
        idx.postings = Postings::Owned { keys, off, ids };
    }
    idx
}

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

const STDIN_LABEL: &str = "(standard input)";

fn search_stdin_raw(buf: &[u8], matcher: &RegexMatcher) -> Option<FileHits> {
    search_stdin_raw_inv(buf, matcher, false)
}

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

fn serve_display_path<'a>(abs: &'a str, root: &str) -> &'a str {
    let prefix = root.strip_suffix('/').unwrap_or(root);
    if let Some(rest) = abs.strip_prefix(prefix) {
        if let Some(rel) = rest.strip_prefix('/') {
            if !rel.is_empty() {
                return rel;
            }
        }
    }
    if let Ok(rel) = std::path::Path::new(abs).strip_prefix(std::path::Path::new(root)) {
        if let Some(s) = rel.to_str() {
            if !s.is_empty() {
                let off = abs.len() - s.len();
                return &abs[off..];
            }
        }
    }
    abs
}
fn matched_file_count(ord: &[u32], loc: &[(u32, u32)]) -> usize {
    let mut seen: HashSet<u32> = HashSet::with_capacity(ord.len().min(1024));
    for &i in ord {
        seen.insert(loc[i as usize].0);
    }
    seen.len()
}
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

fn refuse_build_file(p: &std::path::Path, e: &dyn std::fmt::Display) -> ! {
    eprintln!("nkg: cannot read {}: {e}", p.display());
    std::process::exit(2);
}

struct QueryPhases {
    on: bool,
    load: f64,
    walk: f64,
    rank: f64,
    verify: f64,
    sort: f64,
    tail: Instant,
    rows: u64,
}

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
    let idx_canon = std::fs::canonicalize(idx_path).ok();
    let t_scan = Instant::now();
    let entries: Vec<(String, GramSet)> = paths
        .par_iter()
        .filter_map(|p| {
            let tc = Instant::now();
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
    pairs.par_sort_unstable();
    let sort_ms = ms(&t_sort);
    let t_asm = Instant::now();
    let n = pairs.len();
    let mut keys: Vec<u32> = Vec::with_capacity(n / 8 + 16);
    let mut off: Vec<u32> = Vec::with_capacity(n / 8 + 17);
    let mut ids: Vec<u32> = Vec::with_capacity(n);
    off.push(0);
    let mut prev_gram: u32 = 0;
    for (i, &(g, id)) in pairs.iter().enumerate() {
        if i == 0 || g != prev_gram {
            if i != 0 {
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

#[cfg(unix)]
struct CachedFd {
    fd: std::os::unix::io::RawFd,
    len: u64,
    modified: std::time::SystemTime,
}

#[cfg(unix)]
impl Drop for CachedFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

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
            let _ = nfiles;
            FdCache {}
        }
    }
}

#[cfg(unix)]
fn bump_nofile_for_cache(want_files: usize) {
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
#[cfg(not(unix))]
fn bump_nofile_for_cache(_want_files: usize) {}

#[cfg(unix)]
fn pread_all(fd: std::os::unix::io::RawFd, buf: &mut Vec<u8>) -> std::io::Result<()> {
    let mut off: libc::off_t = 0;
    loop {
        if buf.len() == buf.capacity() {
            buf.reserve(8 * 1024);
        }
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
        unsafe {
            buf.set_len(buf.len() + n);
        }
    }
}

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
    let hit_fd: Option<std::os::unix::io::RawFd> = 'hit: {
        let guard = slot.lock().unwrap_or_else(|e| e.into_inner());
        let e = match guard.as_ref() {
            Some(e) => e,
            None => break 'hit None,
        };
        let fm = {
            use std::os::unix::io::FromRawFd;
            let borrowed = unsafe { std::mem::ManuallyDrop::new(std::fs::File::from_raw_fd(e.fd)) };
            match borrowed.metadata() {
                Ok(m) => m,
                Err(_) => break 'hit None,
            }
        };
        use std::os::unix::fs::MetadataExt;
        if fm.len() != e.len || fm.modified().ok() != Some(e.modified) {
            break 'hit None;
        }
        let live = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return plain_open_read(path, buf, follow),
        };
        if live.dev() != fm.dev() || live.ino() != fm.ino() {
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
                *slot.lock().unwrap_or_else(|e| e.into_inner()) = None;
                return read_verify_bytes(fdc, path, buf, true, follow);
            }
            Err(e) => return Err(e),
        }
    }
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
    let fresh = {
        use std::os::unix::io::IntoRawFd;
        f.into_raw_fd()
    };
    let fd = {
        let mut guard = slot.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(e) if e.len == flen && e.modified == fmod => {
                let fd = e.fd;
                unsafe {
                    libc::close(fresh);
                }
                fd
            }
            _ => {
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
    #[serde(default)]
    ignore_case: bool,
    #[serde(default)]
    before: usize,
    #[serde(default)]
    after: usize,
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
    #[serde(default)]
    qroot: String,
    #[serde(default)]
    display_root: String,
}

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
static STATS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn rank_ors_rooted(
    idx: &Index,
    ors: &[Vec<u32>],
    path_bonus: &dyn Fn(&str) -> bool,
    qrel: Option<&std::path::Path>,
    display_root: &str,
) -> (Vec<u32>, Vec<f64>) {
    let n = idx.files.len() as f64;
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
                        runs.push(run.to_vec());
                        Some(runs.len() - 1)
                    }
                })
                .collect()
        })
        .collect();
    let mut occ: Vec<(&[u32], f64)> = vec![];
    let mut cand: Vec<u32> = vec![];
    let mut tmp: Vec<u32> = vec![];
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

fn raw_order(scores: &[f64]) -> Vec<u32> {
    let mut ord: Vec<u32> = (0..scores.len() as u32).collect();
    ord.sort_by(|a, b| {
        scores[*b as usize]
            .partial_cmp(&scores[*a as usize])
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    ord
}

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

fn banked_text<'a>(fh: &'a FileHits, m: &HitMeta) -> std::borrow::Cow<'a, str> {
    banked_slice(&fh.arena, m.start, m.end)
}

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

fn ctx_group_lines(files: &[FileHits], fi: usize, mis: &[usize]) -> Vec<u64> {
    let mut v: Vec<u64> = mis.iter().map(|&mi| files[fi].metas[mi].line).collect();
    v.sort();
    v.dedup();
    v
}

fn best_hit_score(file_score: f64) -> f64 {
    file_score - 1.0 / 1e6
}

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
            if log_exit {
                eprintln!("nkg: early exit after {done} of {} files", order.len());
            }
            break;
        }
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

const MAX_SERVE_LINE_BYTES: u64 = 1 << 20;
const MAX_SERVE_CONNECTIONS: usize = 64;

const SERVE_EMIT_BYTES: usize = 64 * 1024;

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
        let mut ph = QueryPhases::new();
        let mut broken = false;
        let mut ctx_asked = false;
        let latch = AtomicBool::new(false);
        let mut verify_err = false;
        match serde_json::from_str::<Query>(line.trim()) {
            Err(_) => {}
            Ok(q) => {
                ctx_asked = q.before > 0 || q.after > 0;
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
                        let qrel: Option<std::path::PathBuf> = if q.qroot.is_empty() {
                            None
                        } else {
                            std::path::Path::new(&q.qroot)
                                .strip_prefix(&idx.root)
                                .ok()
                                .map(|r| r.to_owned())
                        };
                        let q_outside = !q.qroot.is_empty() && qrel.is_none();
                        let all_files = || {
                            (0..idx.files.len() as u32)
                                .map(|id| {
                                    let stored = &idx.files[id as usize];
                                    let rp = daemon_rank_path(
                                        stored,
                                        &idx.root,
                                        qrel.as_deref(),
                                        &q.display_root,
                                    );
                                    let depth =
                                        std::path::Path::new(rp.as_ref()).components().count()
                                            as f64;
                                    let bonus =
                                        if q_pats.iter().any(|pat| rp.contains(pat.as_str())) {
                                            100.0
                                        } else {
                                            0.0
                                        };
                                    (id, bonus - depth)
                                })
                                .collect()
                        };
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
                        let t_sort = Instant::now();
                        apply_max_count(&mut files, q.max_count);
                        verify_err |= take_verify_io_error(&latch);
                        let (hit_scores, loc) = flat_scores(&files);
                        let mut ord = raw_order(&hit_scores);
                        if let Some(n) = q.top {
                            ord.truncate(n);
                        }
                        ph.sort = t_sort.elapsed().as_secs_f64() * 1e3;
                        ph.rows = ord.len() as u64;
                        ph.tail = Instant::now();
                        let mut esc: Vec<Option<Vec<u8>>> = vec![None; idx.files.len()];
                        for &i in &ord {
                            let (fi, _) = loc[i as usize];
                            let pid = files[fi as usize].pid as usize;
                            if esc[pid].is_none() {
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
                        let mut buf: Vec<u8> = Vec::with_capacity(SERVE_EMIT_BYTES);
                        if ctx_on {
                            let mut fscore = vec![0.0f64; idx.files.len()];
                            for (id, s) in &order {
                                fscore[*id as usize] = *s;
                            }
                            for (fi, mis) in ctx_file_groups(&files, &loc, &ord) {
                                if broken {
                                    break;
                                }
                                let fh = &files[fi];
                                let pe = esc[fh.pid as usize].as_ref().unwrap();
                                let nlines = fh.line_starts.len() as u64;
                                let mlines = ctx_group_lines(&files, fi, &mis);
                                let mut k = 0usize;
                                for (lo, hi) in compute_groups(&mlines, q.before, q.after) {
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
                        if writer.write_all(&buf).is_err() {
                            broken = true;
                        }
                    }
                }
            }
        }
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

#[cfg(target_os = "linux")]
fn proc_starttime(pid: u32) -> Option<u64> {
    let data = std::fs::read(format!("/proc/{pid}/stat")).ok()?;
    let text = String::from_utf8_lossy(&data);
    let after = text.rfind(')')?;
    let fields: Vec<&str> = text[after + 1..].split_whitespace().collect();
    fields.get(19)?.parse::<u64>().ok()
}
#[cfg(not(target_os = "linux"))]
fn proc_starttime(_pid: u32) -> Option<u64> {
    None
}
fn pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(unix)]
    {
        let r = unsafe { libc::kill(pid as i32, 0) };
        if r == 0 {
            return true;
        }
        let e = std::io::Error::last_os_error().raw_os_error();
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

enum ServeProbe {
    Hit(ServeRows),
    MissSilent,
    MissWarn(String),
}

struct WireRow<'a> {
    path: &'a [u8],
    line: u64,
    text: &'a [u8],
}

fn scan_wire_row(line: &[u8]) -> Option<WireRow<'_>> {
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

fn push_unescaped_json(dst: &mut Vec<u8>, s: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    fn hex(b: u8) -> Option<u8> {
        HEX.iter().position(|&h| h == b).map(|p| p as u8)
    }
    let mut start = 0usize;
    let mut i = 0usize;
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
            _ => {}
        }
        i = (i + 1).min(s.len());
        start = i;
    }
    dst.extend_from_slice(&s[start..]);
}
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
struct MatchSpec<'a> {
    patterns: &'a [String],
    fixed: bool,
    word: bool,
    invert: bool,
    max_count: Option<usize>,
    qroot: &'a str,
    display_root: &'a str,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum ServeMode {
    Aggregate,
    Json,
    Text,
    Context,
}

const SERVE_FLUSH_BYTES: usize = 256 * 1024;

#[derive(Default)]
struct WireScratch {
    path: Vec<u8>,
    text: Vec<u8>,
}

struct ServeRows {
    buf: Vec<u8>,
    files: HashMap<Vec<u8>, usize>,
    matches: usize,
    done: bool,
    ctx_echo: bool,
    verify_err: bool,
    emitted: bool,
}

impl ServeRows {
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

    fn matched(&self) -> usize {
        self.files.len()
    }
}

struct ServeQuery<'a> {
    pattern: &'a str,
    top: Option<usize>,
    ignore_case: bool,
    mspec: &'a MatchSpec<'a>,
    mode: ServeMode,
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

fn serve_mode(
    quiet: bool,
    count_mode: bool,
    files_only: bool,
    ctx_on: bool,
    format_text: bool,
) -> ServeMode {
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

fn finish_serve_response(rows: &ServeRows, r: &ServeQuery<'_>, t0: Instant) {
    let matcher = r.matcher.as_ref();
    let matched = rows.matched();
    if r.count_mode || r.files_only {
        if !r.quiet {
            let agg = rows.aggregates();
            let refs: Vec<(&str, usize)> = agg.iter().map(|(p, n)| (p.as_str(), *n)).collect();
            let stdout = std::io::stdout();
            let mut writer = std::io::BufWriter::with_capacity(1024 * 1024, stdout.lock());
            write_aggregates(&mut writer, &refs, r.files_only);
            stdout_flush(&mut writer);
        }
    } else if r.ctx_on() && !r.quiet {
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
#[derive(Debug)]
struct ServeFail {
    msg: String,
    bad_regex: bool,
    emitted: bool,
}

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
    let path = String::from_utf8_lossy(&scratch.path);
    let text = String::from_utf8_lossy(&scratch.text);
    match matcher {
        Some(m) => emit_text_row_colored(out, &path, row.line, &text, m),
        None => emit_text_row(out, &path, row.line, &text),
    }
}

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
        return if rows.emitted {
            eprintln!("nkg: server closed the connection mid-response");
            std::process::exit(2);
        } else {
            ServeProbe::MissWarn(UNREACHABLE.to_string())
        };
    }
    ServeProbe::Hit(rows)
}
fn push_escaped_json(out: &mut Vec<u8>, s: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let b = s.as_bytes();
    let mut start = 0usize;
    let mut i = 0usize;
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

const EMIT_PAR_MIN_BYTES: usize = 64 * 1024;
const EMIT_CHUNK_BYTES: usize = 1024 * 1024;
const EMIT_CHUNK_MAX_ROWS: usize = 4096;
const FRAME_TEXT: usize = 128;
const FRAME_JSON: usize = 160;

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

fn emit_plan(rows: usize, est_bytes: usize) -> Option<usize> {
    if rows == 0 || est_bytes < EMIT_PAR_MIN_BYTES {
        return None;
    }
    let avg = (est_bytes / rows).max(1);
    Some((EMIT_CHUNK_BYTES / avg).clamp(1, EMIT_CHUNK_MAX_ROWS))
}

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
fn emit_text_row(buf: &mut Vec<u8>, path: &str, line: u64, text: &str) {
    buf.extend_from_slice(path.as_bytes());
    buf.push(b':');
    push_line_no(buf, line);
    buf.push(b':');
    buf.extend_from_slice(text.as_bytes());
    buf.push(b'\n');
}

fn emit_ctx_row(buf: &mut Vec<u8>, path: &str, line: u64, text: &str) {
    buf.extend_from_slice(path.as_bytes());
    buf.push(b':');
    push_line_no(buf, line);
    buf.push(b'-');
    buf.extend_from_slice(text.as_bytes());
    buf.push(b'\n');
}

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

fn render_served_context(
    raw: &[u8],
    before: usize,
    after: usize,
    sep: &str,
    matcher: Option<&RegexMatcher>,
) -> Vec<u8> {
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

fn stdout_err(e: std::io::Error) -> ! {
    if e.kind() == std::io::ErrorKind::BrokenPipe {
        std::process::exit(0);
    }
    eprintln!("nkg: stdout: {e}");
    std::process::exit(2);
}

fn stdout_write_all(w: &mut impl Write, data: &[u8]) {
    if let Err(e) = w.write_all(data) {
        stdout_err(e);
    }
}

fn stdout_flush(w: &mut impl Write) {
    if let Err(e) = w.flush() {
        stdout_err(e);
    }
}
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

fn main() {
    let raw: Vec<String> = std::env::args().skip(1).collect();
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
    let mut ctx_a: Option<usize> = None;
    let mut ctx_b: Option<usize> = None;
    let mut ctx_c: Option<usize> = None;
    let mut max_count: Option<usize> = None;
    let mut patterns_e: Vec<String> = vec![];
    let mut pattern_files: Vec<String> = vec![];
    let mut explicit_patterns = false;
    let mut fixed_strings = false;
    let mut invert_match = false;
    let mut word_regexp = false;
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
            match raw[i][2..].parse::<usize>() {
                Ok(n) => max_count = Some(n),
                Err(_) => {
                    eprintln!("nkg: bad -m {:?}: expected a number", raw[i]);
                    usage();
                }
            }
        } else if raw[i] == "-e" || raw[i] == "--regexp" {
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
            eprintln!("nkg: {} is not supported", raw[i]);
            usage();
        } else if raw[i] == "--no-pcre2" || raw[i] == "--no-encoding" {
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
            match raw[i][2..].parse::<usize>() {
                Ok(n) => ctx_a = Some(n),
                Err(_) => {
                    eprintln!("nkg: bad -A {:?}: expected a number", raw[i]);
                    usage();
                }
            }
        } else if raw[i].starts_with("-B") && !raw[i].starts_with("--") && raw[i].len() > 2 {
            match raw[i][2..].parse::<usize>() {
                Ok(n) => ctx_b = Some(n),
                Err(_) => {
                    eprintln!("nkg: bad -B {:?}: expected a number", raw[i]);
                    usage();
                }
            }
        } else if raw[i].starts_with("-C") && !raw[i].starts_with("--") && raw[i].len() > 2 {
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
            for c in raw[i][1..].chars() {
                match c {
                    'i' => ignore_case = true,
                    'q' => quiet = true,
                    'c' => count_mode = true,
                    'l' => files_only = true,
                    'F' => fixed_strings = true,
                    'v' => invert_match = true,
                    'w' => word_regexp = true,
                    _ => {}
                }
            }
        } else {
            pos.push(raw[i].clone());
        }
        i += 1;
    }
    if explicit_patterns {
        if pos.len() > 1 {
            usage();
        }
    } else if pos.is_empty() || pos.len() > 2 {
        usage();
    }
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
        patterns.push("\\b\\B".to_string());
        fixed_strings = false;
    }
    if !explicit_patterns {
        patterns.push(pos[0].clone());
    }
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
    if port.is_some() && use_index.is_some() {
        eprintln!("nkg: --use-index cannot be combined with --port");
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
    let walk_opts = WalkOptions {
        hidden: walk_hidden,
        no_ignore: walk_no_ignore,
        follow: walk_follow,
        max_depth: walk_max_depth,
        max_filesize: walk_max_filesize,
        globs: walk_globs,
    };
    let color_on = format_text && color_enabled(color_when);
    let ctx_after = ctx_a.or(ctx_c).unwrap_or(0);
    let ctx_before = ctx_b.or(ctx_c).unwrap_or(0);
    let ctx_on = ctx_after > 0 || ctx_before > 0;
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
    let sq = ServeQuery {
        pattern: &pattern,
        top,
        ignore_case,
        mspec: &mspec,
        mode: serve_mode(quiet, count_mode, files_only, ctx_on, format_text),
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
    let match_limit = files_only.then_some(1u64);
    let mut hits: Vec<FileHits> = vec![];

    let mut walk_error = false;
    let verify_latch = AtomicBool::new(false);
    let mut ptab: Vec<String> = vec![];
    let mut hits_indexed = false;
    let files: usize;
    let mut load_ms = 0u128;
    let idx_opt: Option<Index> = if stdin_mode {
        None
    } else if let Some(idx_path) = &use_index {
        let t_load = Instant::now();
        let idx = load_index_for_query(idx_path, &root);
        let load = t_load.elapsed();
        load_ms = load.as_millis();
        ph.load = load.as_secs_f64() * 1e3;
        Some(idx)
    } else {
        None
    };
    if stdin_mode {
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
        let stdin_hit = if invert_match {
            search_stdin_raw_inv(&input, &matcher, true)
        } else {
            search_stdin_raw(&input, &matcher)
        };
        if quiet {
            quiet_exit(stdin_hit.is_some(), files, load_ms, t0, false);
        }
        hits = stdin_hit.map(|h| vec![h]).unwrap_or_default();
        apply_max_count(&mut hits, max_count);
        if ctx_on {
            for fh in hits.iter_mut() {
                attach_context(fh, &input);
            }
        }
    } else if let Some(idx) = &idx_opt {
        let mut scores = vec![0.0f64; idx.files.len()];
        let mut order: Vec<u32> = vec![];
        let mut fallback =
            ignore_case || invert_match || walk_hidden || walk_no_ignore || walk_follow;
        match if fallback {
            None
        } else {
            query_grams_multi(&patterns, fixed_strings)
        } {
            None => fallback = true,
            Some(ors) => {
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
        } else {
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
    let t_sort = Instant::now();
    apply_max_count(&mut hits, max_count);
    let (hit_scores, loc) = flat_scores(&hits);
    let mut ord = raw_order(&hit_scores);
    if let Some(n) = top {
        ord.truncate(n);
    }
    ph.sort = t_sort.elapsed().as_secs_f64() * 1e3;
    ph.tail = Instant::now();
    ph.rows = ord.len() as u64;
    let matches = ord.len();
    let matched = matched_file_count(&ord, &loc);
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
mod context_tests {
    use super::*;

    #[test]
    fn groups_merge_overlap_and_adjacency() {
        assert_eq!(compute_groups(&[2, 4], 1, 1), vec![(1, 5)]);
        assert_eq!(compute_groups(&[3, 7], 1, 1), vec![(2, 4), (6, 8)]);
    }
    #[test]
    fn groups_clamp_top_and_split() {
        assert_eq!(compute_groups(&[1], 2, 1), vec![(1, 2)]);
        assert_eq!(compute_groups(&[1, 8], 1, 1), vec![(1, 2), (7, 9)]);
        assert!(compute_groups(&[], 2, 2).is_empty());
        assert_eq!(compute_groups(&[5], 0, 0), vec![(5, 5)]);
    }

    #[test]
    fn attach_remap_is_byte_identical() {
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
        assert_eq!(ctx_line_text(&attached, 1), "first\r");
        assert_eq!(ctx_line_text(&attached, 3), "middle");
        assert_eq!(ctx_line_text(&attached, 4), "needle two");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn served_context_renders_rg_shape() {
        let raw = b"{\"path\":\"b.txt\",\"line\":2,\"text\":\"hit B\",\"score\":1.0}\n\
                    {\"path\":\"b.txt\",\"line\":1,\"text\":\"ctx B\",\"score\":1.0,\"ctx\":true}\n\
                    {\"path\":\"a.txt\",\"line\":1,\"text\":\"hit A1\",\"score\":0.0}\n\
                    {\"path\":\"a.txt\",\"line\":9,\"text\":\"hit A2\",\"score\":0.0}\n";
        let out = render_served_context(raw, 1, 1, "--", None);
        assert_eq!(
            &out,
            b"b.txt:1-ctx B\nb.txt:2:hit B\na.txt:1:hit A1\n--\na.txt:9:hit A2\n"
        );
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
        let dir = std::env::temp_dir().join(format!("nkg_gitskip_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        plant(&dir);
        let root = dir.clone();
        let has_git =
            |s: &std::collections::HashSet<String>| s.iter().any(|p| p.starts_with(".git"));
        let d = names(&root, &opts(false, false));
        assert_eq!(
            d,
            std::collections::HashSet::from(["normal.txt".to_string()])
        );
        let h = names(&root, &opts(true, false));
        assert!(h.contains("normal.txt"), "{h:?}");
        assert!(h.contains(".hidden.txt"), "{h:?}");
        assert!(!has_git(&h), "--hidden must not descend .git: {h:?}");
        let n = names(&root, &opts(false, true));
        assert!(!has_git(&n), "--no-ignore alone keeps hidden skip: {n:?}");
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
        let b = [0xffu8, 0xff, 0xff, 0xff, 0x7f, 0];
        assert!(
            get_varint(&b, 0).is_none(),
            "must refuse a value wider than u32"
        );
    }

    #[test]
    fn varint_would_not_silently_decode_to_an_in_range_id() {
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
        let wire =
            br#"{"path":"a\"b\\c.txt","line":7,"text":"q\"r\\s {\"path\":\"z\"}","score":1.0}"#;
        let row = scan_wire_row(wire).expect("complete row");
        assert_eq!(row.path, br#"a\"b\\c.txt"#);
        assert_eq!(row.line, 7);
        assert_eq!(row.text, br#"q\"r\\s {\"path\":\"z\"}"#);
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
        assert_eq!(rows.matches, 3);
        assert_eq!(rows.matched(), 1);
        assert_eq!(String::from_utf8(out).unwrap(), "a.txt:4:ok\n");
    }

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
        const MAX_OVER_RESERVE: f64 = 2.0;

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
        let plan = emit_plan(240, 240 * 560 * 1024).expect("134 MB of output renders in parallel");
        assert!(240usize.div_ceil(plan) >= rayon::current_num_threads());
        assert_eq!(emit_plan(51_410, 51_410 * 160), Some(4096));
        assert_eq!(emit_plan(4000, 4096), None);
        assert_eq!(emit_plan(0, 0), None);
    }

    #[test]
    fn top_truncation_sizes_from_the_rows_that_print() {
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
