use grep_regex::RegexMatcher;
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
mod index_format;
mod matcher;
mod prefilter;
mod verify;
mod walk;
use crate::verify::{
    bump_nofile_for_cache, open_verify_file, search_stdin_raw, search_stdin_raw_inv,
    take_verify_io_error, verify_one_raw, verify_one_raw_cached, verify_one_raw_cached_ctx,
    verify_one_raw_ctx, CachedVerify, FdCache, FileHits, HitMeta, VerifyInput,
};
use cli::{
    color_enabled, colorize_spans, parse_color_when, print_help, print_version, usage, ColorWhen,
};
use index_format::{
    encode_index_bin, index_header, parse_index_auto, read_index_bytes, read_index_header_bytes,
    validate_stored_files, write_index_file, Index, Postings,
};
use matcher::{
    apply_max_count, build_matcher_opts, combine_patterns, grams_of, query_grams,
    query_grams_multi, split_pattern_lines, GramSet,
};
use walk::{
    canon_root, is_binary, parse_filesize, refuse_bad_filesize, root_cookie, strip_dot_slash,
    walk_files, WalkOptions,
};

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

pub(crate) fn attach_context(fh: &mut FileHits, buf: &[u8]) {
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
