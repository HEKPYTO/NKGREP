use crate::cli::colorize_spans;
use crate::index_format::Index;
use crate::push_wire_text_row;
use crate::rank::{banked_text, compute_groups, ctx_group_lines, ctx_line_text};
use crate::serve::{path_of, push_escaped_json, push_line_no, WireScratch};
use crate::verify::FileHits;
use grep_regex::RegexMatcher;

#[cfg(test)]
use crate::rank::{ctx_file_groups, flat_scores, raw_order};
#[cfg(test)]
use crate::verify::{verify_one_raw_ctx, HitMeta, VerifyInput};
#[cfg(test)]
use rayon::prelude::*;
#[cfg(test)]
use std::sync::atomic::AtomicBool;

pub(crate) fn render_buffered_text(raw: &[u8], matcher: Option<&RegexMatcher>) -> Vec<u8> {
    let mut out = vec![];
    let mut scratch = WireScratch::default();
    for line in raw.split(|&b| b == b'\n') {
        if !line.is_empty() {
            push_wire_text_row(&mut out, line, matcher, &mut scratch);
        }
    }
    out
}

pub(crate) const EMIT_PAR_MIN_BYTES: usize = 64 * 1024;
pub(crate) const EMIT_CHUNK_BYTES: usize = 1024 * 1024;
pub(crate) const EMIT_CHUNK_MAX_ROWS: usize = 4096;
pub(crate) const FRAME_TEXT: usize = 128;
pub(crate) const FRAME_JSON: usize = 160;

pub(crate) struct EmitSource<'a> {
    pub(crate) hits: &'a [FileHits],
    pub(crate) loc: &'a [(u32, u32)],
    pub(crate) idx_opt: &'a Option<Index>,
    pub(crate) ptab: &'a [String],
    pub(crate) hits_indexed: bool,
    pub(crate) color_on: bool,
    pub(crate) matcher: &'a RegexMatcher,
}

impl EmitSource<'_> {
    fn path(&self, pid: usize) -> &str {
        path_of(self.idx_opt, self.ptab, self.hits_indexed, pid)
    }
}

pub(crate) fn est_output_bytes(
    rows: &[u32],
    hits: &[FileHits],
    loc: &[(u32, u32)],
    frame: usize,
) -> usize {
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

pub(crate) fn emit_plan(rows: usize, est_bytes: usize) -> Option<usize> {
    if rows == 0 || est_bytes < EMIT_PAR_MIN_BYTES {
        return None;
    }
    let avg = (est_bytes / rows).max(1);
    Some((EMIT_CHUNK_BYTES / avg).clamp(1, EMIT_CHUNK_MAX_ROWS))
}

pub(crate) fn ctx_group_bytes(
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

pub(crate) fn render_text_chunk(src: &EmitSource<'_>, chunk: &[u32]) -> Vec<u8> {
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

pub(crate) fn render_json_chunk(
    src: &EmitSource<'_>,
    esc: &[Option<Vec<u8>>],
    chunk: &[u32],
) -> Vec<u8> {
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

pub(crate) fn render_ctx_chunk(
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

pub(crate) fn emit_raw_with_path(
    buf: &mut Vec<u8>,
    path_esc: &[u8],
    line: u64,
    text: &str,
    score: f64,
) {
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
pub(crate) fn emit_text_row(buf: &mut Vec<u8>, path: &str, line: u64, text: &str) {
    buf.extend_from_slice(path.as_bytes());
    buf.push(b':');
    push_line_no(buf, line);
    buf.push(b':');
    buf.extend_from_slice(text.as_bytes());
    buf.push(b'\n');
}

pub(crate) fn emit_ctx_row(buf: &mut Vec<u8>, path: &str, line: u64, text: &str) {
    buf.extend_from_slice(path.as_bytes());
    buf.push(b':');
    push_line_no(buf, line);
    buf.push(b'-');
    buf.extend_from_slice(text.as_bytes());
    buf.push(b'\n');
}

pub(crate) fn emit_ctx_json(
    buf: &mut Vec<u8>,
    path_esc: &[u8],
    line: u64,
    text: &str,
    file_score: f64,
) {
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

pub(crate) fn render_served_context(
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

pub(crate) fn emit_text_row_colored(
    buf: &mut Vec<u8>,
    path: &str,
    line: u64,
    text: &str,
    matcher: &RegexMatcher,
) {
    let colored = colorize_spans(text, matcher);
    emit_text_row(buf, path, line, &colored);
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
