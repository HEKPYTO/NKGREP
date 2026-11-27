use crate::index_format::Index;
use crate::prefilter;
use crate::serve::serve_display_path;
use crate::verify::{FileHits, HitMeta};
use crate::walk::strip_dot_slash;
use crate::{stdout_write_all, PHASE_TIMING};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::Write;
use std::time::Instant;

pub(crate) fn matched_file_count(ord: &[u32], loc: &[(u32, u32)]) -> usize {
    let mut seen: HashSet<u32> = HashSet::with_capacity(ord.len().min(1024));
    for &i in ord {
        seen.insert(loc[i as usize].0);
    }
    seen.len()
}
pub(crate) fn write_aggregates(w: &mut impl Write, rows: &[(&str, usize)], files_only: bool) {
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

pub(crate) struct QueryPhases {
    pub(crate) on: bool,
    pub(crate) load: f64,
    pub(crate) walk: f64,
    pub(crate) rank: f64,
    pub(crate) verify: f64,
    pub(crate) sort: f64,
    pub(crate) tail: Instant,
    pub(crate) rows: u64,
}

impl QueryPhases {
    pub(crate) fn new() -> Self {
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

    pub(crate) fn report(&self) {
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

#[derive(Serialize, Deserialize)]
pub(crate) struct Query {
    pub(crate) pattern: String,
    pub(crate) top: Option<usize>,
    #[serde(default)]
    pub(crate) ignore_case: bool,
    #[serde(default)]
    pub(crate) before: usize,
    #[serde(default)]
    pub(crate) after: usize,
    #[serde(default)]
    pub(crate) word: bool,
    #[serde(default)]
    pub(crate) invert: bool,
    #[serde(default)]
    pub(crate) max_count: Option<usize>,
    #[serde(default)]
    pub(crate) patterns: Vec<String>,
    #[serde(default)]
    pub(crate) fixed: bool,
    #[serde(default)]
    pub(crate) qroot: String,
    #[serde(default)]
    pub(crate) display_root: String,
}

pub(crate) fn rank_ors(
    idx: &Index,
    ors: &[Vec<u32>],
    path_bonus: &dyn Fn(&str) -> bool,
) -> (Vec<u32>, Vec<f64>) {
    rank_ors_rooted(idx, ors, path_bonus, None, "")
}
pub(crate) fn daemon_rank_path<'a>(
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
pub(crate) static STATS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(crate) fn rank_ors_rooted(
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

pub(crate) fn raw_order(scores: &[f64]) -> Vec<u32> {
    let mut ord: Vec<u32> = (0..scores.len() as u32).collect();
    ord.sort_by(|a, b| {
        scores[*b as usize]
            .partial_cmp(&scores[*a as usize])
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    ord
}

pub(crate) fn flat_scores(files: &[FileHits]) -> (Vec<f64>, Vec<(u32, u32)>) {
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

pub(crate) fn banked_text<'a>(fh: &'a FileHits, m: &HitMeta) -> std::borrow::Cow<'a, str> {
    banked_slice(&fh.arena, m.start, m.end)
}

pub(crate) fn compute_groups(lines: &[u64], before: usize, after: usize) -> Vec<(u64, u64)> {
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

pub(crate) fn ctx_line_text<'a>(fh: &'a FileHits, line_no: u64) -> std::borrow::Cow<'a, str> {
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

pub(crate) fn ctx_file_groups(
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

pub(crate) fn ctx_group_lines(files: &[FileHits], fi: usize, mis: &[usize]) -> Vec<u64> {
    let mut v: Vec<u64> = mis.iter().map(|&mi| files[fi].metas[mi].line).collect();
    v.sort();
    v.dedup();
    v
}

fn best_hit_score(file_score: f64) -> f64 {
    file_score - 1.0 / 1e6
}

pub(crate) fn verify_batched<F>(
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
