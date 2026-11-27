use grep_regex::RegexMatcher;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;
mod cli;
mod emit;
mod index_format;
mod matcher;
mod prefilter;
mod rank;
mod serve;
mod verify;
mod walk;
#[cfg(test)]
use crate::emit::render_served_context;
use crate::emit::{
    ctx_group_bytes, emit_plan, emit_text_row, emit_text_row_colored, est_output_bytes,
    render_ctx_chunk, render_json_chunk, render_text_chunk, EmitSource, FRAME_JSON, FRAME_TEXT,
};
#[cfg(test)]
use crate::rank::{banked_text, compute_groups, ctx_line_text};
use crate::rank::{
    ctx_file_groups, flat_scores, matched_file_count, rank_ors, raw_order, verify_batched,
    write_aggregates, QueryPhases, STATS,
};
use crate::serve::{
    client_query, cmd_serve, finish_serve_response, path_of, push_escaped_json,
    push_unescaped_json, scan_wire_row, serve_eligible_root, serve_mode, try_serve_query,
    MatchSpec, ServeProbe, ServeQuery, WireScratch,
};
use crate::verify::{
    open_verify_file, search_stdin_raw, search_stdin_raw_inv, take_verify_io_error, verify_one_raw,
    verify_one_raw_ctx, FileHits, VerifyInput,
};
use cli::{color_enabled, parse_color_when, print_help, print_version, usage, ColorWhen};
use index_format::{
    encode_index_bin, parse_index_auto, read_index_bytes, validate_stored_files, write_index_file,
    Index, Postings,
};
use matcher::{
    apply_max_count, build_matcher_opts, combine_patterns, grams_of, query_grams_multi,
    split_pattern_lines, GramSet,
};
use walk::{
    canon_root, is_binary, parse_filesize, refuse_bad_filesize, root_cookie, strip_dot_slash,
    walk_files, WalkOptions,
};

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

const STDIN_LABEL: &str = "(standard input)";

fn refuse_build_file(p: &std::path::Path, e: &dyn std::fmt::Display) -> ! {
    eprintln!("nkg: cannot read {}: {e}", p.display());
    std::process::exit(2);
}

pub(crate) static PHASE_TIMING: std::sync::LazyLock<bool> =
    std::sync::LazyLock::new(|| std::env::var_os("NKG_PHASE_TIMING").is_some());

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

pub(crate) fn push_wire_text_row(
    out: &mut Vec<u8>,
    wire: &[u8],
    matcher: Option<&RegexMatcher>,
    scratch: &mut WireScratch,
) {
    let Some(row) = scan_wire_row(wire) else {
        return;
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

fn stdout_err(e: std::io::Error) -> ! {
    if e.kind() == std::io::ErrorKind::BrokenPipe {
        std::process::exit(0);
    }
    eprintln!("nkg: stdout: {e}");
    std::process::exit(2);
}

pub(crate) fn stdout_write_all(w: &mut impl Write, data: &[u8]) {
    if let Err(e) = w.write_all(data) {
        stdout_err(e);
    }
}

pub(crate) fn stdout_flush(w: &mut impl Write) {
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
                            Some(1),
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
