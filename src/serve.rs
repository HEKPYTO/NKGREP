use crate::emit::{emit_ctx_json, emit_raw_with_path, render_buffered_text, render_served_context};
use crate::index_format::{
    index_header, parse_index_auto, read_index_bytes, read_index_header_bytes,
    validate_stored_files, Index,
};
use crate::matcher::{
    apply_max_count, build_matcher_opts, combine_patterns, query_grams, query_grams_multi,
};
use crate::rank::{
    banked_text, compute_groups, ctx_file_groups, ctx_group_lines, ctx_line_text, daemon_rank_path,
    flat_scores, rank_ors_rooted, raw_order, verify_batched, write_aggregates, Query, QueryPhases,
};
use crate::verify::{
    bump_nofile_for_cache, take_verify_io_error, verify_one_raw_cached, verify_one_raw_cached_ctx,
    CachedVerify, FdCache, FileHits,
};
use crate::walk::{canon_root, root_cookie, strip_dot_slash};
use crate::{push_wire_text_row, stdout_flush, stdout_write_all};
use grep_regex::RegexMatcher;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};
pub(crate) fn serve_eligible_root(idx_path: &str, query_root: &std::path::Path) -> bool {
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
pub(crate) fn load_index_for_serve(idx_path: &str) -> Index {
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
pub(crate) fn serve_display_path<'a>(abs: &'a str, root: &str) -> &'a str {
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
pub(crate) const MAX_SERVE_LINE_BYTES: u64 = 1 << 20;
pub(crate) const MAX_SERVE_CONNECTIONS: usize = 64;

pub(crate) const SERVE_EMIT_BYTES: usize = 64 * 1024;

pub(crate) fn serve_emit_line(
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
pub(crate) fn handle_client(stream: TcpStream, idx: Arc<Index>, fdc: Arc<FdCache>) {
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
pub(crate) fn serve_info_path(idx_path: &str) -> String {
    format!("{idx_path}.serve.json")
}

#[cfg(target_os = "linux")]
pub(crate) fn proc_starttime(pid: u32) -> Option<u64> {
    let data = std::fs::read(format!("/proc/{pid}/stat")).ok()?;
    let text = String::from_utf8_lossy(&data);
    let after = text.rfind(')')?;
    let fields: Vec<&str> = text[after + 1..].split_whitespace().collect();
    fields.get(19)?.parse::<u64>().ok()
}
#[cfg(not(target_os = "linux"))]
pub(crate) fn proc_starttime(_pid: u32) -> Option<u64> {
    None
}
pub(crate) fn pid_alive(pid: u32) -> bool {
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
pub(crate) struct ServerInfo {
    pub(crate) pid: u32,
    pub(crate) port: u16,
    #[serde(default)]
    pub(crate) starttime: u64,
}

pub(crate) fn save_serve_info(idx_path: &str, port: u16) {
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

pub(crate) enum ServeProbe {
    Hit(ServeRows),
    MissSilent,
    MissWarn(String),
}

pub(crate) struct WireRow<'a> {
    pub(crate) path: &'a [u8],
    pub(crate) line: u64,
    pub(crate) text: &'a [u8],
}

pub(crate) fn scan_wire_row(line: &[u8]) -> Option<WireRow<'_>> {
    fn end_of_str(s: &[u8]) -> Option<usize> {
        let mut i = 0;
        while i <= s.len() {
            let k = i + memchr::memchr2(b'"', b'\\', &s[i..])?;
            if s[k] == b'"' {
                return Some(k);
            }
            i = k + 2;
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

pub(crate) fn push_unescaped_json(dst: &mut Vec<u8>, s: &[u8]) {
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
pub(crate) fn load_serve_port_quiet(idx_path: &str) -> Result<Option<u16>, String> {
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

pub(crate) fn cmd_serve(idx_path: &str, port: u16) {
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
pub(crate) struct MatchSpec<'a> {
    pub(crate) patterns: &'a [String],
    pub(crate) fixed: bool,
    pub(crate) word: bool,
    pub(crate) invert: bool,
    pub(crate) max_count: Option<usize>,
    pub(crate) qroot: &'a str,
    pub(crate) display_root: &'a str,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServeMode {
    Aggregate,
    Json,
    Text,
    Context,
}

pub(crate) const SERVE_FLUSH_BYTES: usize = 256 * 1024;

#[derive(Default)]
pub(crate) struct WireScratch {
    pub(crate) path: Vec<u8>,
    pub(crate) text: Vec<u8>,
}

pub(crate) struct ServeRows {
    pub(crate) buf: Vec<u8>,
    pub(crate) files: HashMap<Vec<u8>, usize>,
    pub(crate) matches: usize,
    pub(crate) done: bool,
    pub(crate) ctx_echo: bool,
    pub(crate) verify_err: bool,
    pub(crate) emitted: bool,
}

impl ServeRows {
    pub(crate) fn aggregates(&self) -> Vec<(String, usize)> {
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

    pub(crate) fn matched(&self) -> usize {
        self.files.len()
    }
}

pub(crate) struct ServeQuery<'a> {
    pub(crate) pattern: &'a str,
    pub(crate) top: Option<usize>,
    pub(crate) ignore_case: bool,
    pub(crate) mspec: &'a MatchSpec<'a>,
    pub(crate) mode: ServeMode,
    pub(crate) matcher: Option<RegexMatcher>,
    pub(crate) group_sep: &'a str,
    pub(crate) ctx_before: usize,
    pub(crate) ctx_after: usize,
    pub(crate) count_mode: bool,
    pub(crate) files_only: bool,
    pub(crate) quiet: bool,
}

impl ServeQuery<'_> {
    pub(crate) fn ctx_on(&self) -> bool {
        self.ctx_before > 0 || self.ctx_after > 0
    }

    pub(crate) fn request(&self) -> Option<String> {
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

pub(crate) fn serve_mode(
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

pub(crate) fn finish_serve_response(rows: &ServeRows, r: &ServeQuery<'_>, t0: Instant) {
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
pub(crate) struct ServeFail {
    pub(crate) msg: String,
    pub(crate) bad_regex: bool,
    pub(crate) emitted: bool,
}

pub(crate) fn read_serve_response(
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

pub(crate) fn client_query(port: u16, q: &ServeQuery<'_>) -> ServeRows {
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
pub(crate) fn try_serve_query(idx_path: &str, q: &ServeQuery<'_>) -> ServeProbe {
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
pub(crate) fn push_escaped_json(out: &mut Vec<u8>, s: &str) {
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
pub(crate) fn push_line_no(buf: &mut Vec<u8>, line: u64) {
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
pub(crate) fn path_of<'a>(
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
                break;
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
