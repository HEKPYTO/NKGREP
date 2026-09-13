//! ONE oracle check: indexed full search must equal scan full search on a
//! planted fixture, including an alternation query. Fails on any divergence.
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_nkg"))
}

fn fixture() -> PathBuf {
    fixture_in("base")
}

fn fixture_in(name: &str) -> PathBuf {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("nkg-oracle-{}-{name}-{n}", std::process::id()));
    for pkg in 0..4 {
        let d = dir.join(format!("pkg_{pkg}"));
        std::fs::create_dir_all(&d).unwrap();
        for f in 0..25 {
            let mut text = String::new();
            for ln in 0..20 {
                text.push_str(&format!("line {ln} filler words config cache token\n"));
            }
            if (pkg + f) % 3 == 0 {
                text.push_str("planted NEEDLE_ALPHA here\n");
            }
            if f % 5 == 0 {
                text.push_str("other needle_1 marker\n");
            }
            std::fs::write(d.join(format!("m_{f}.txt")), text).unwrap();
        }
    }
    // Binary file: NUL in the first 8 KiB forces the index skip; the verify
    // side skips it identically, so indexed==scan holds with zero binary hits.
    let mut bin = b"planted NEEDLE_ALPHA in binary\n".to_vec();
    bin.extend_from_slice(&[0u8; 16]);
    bin.extend_from_slice(b"trailing NEEDLE_ALPHA bytes\n");
    std::fs::write(dir.join("pkg_0").join("bin.dat"), bin).unwrap();
    dir
}

fn run(args: &[&str], cwd: &PathBuf) -> Vec<(String, u64, String)> {
    let out = Command::new(bin())
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap();
    assert!([0, 1].contains(&out.status.code().unwrap()));
    // one JSON object per line
    let mut rows = HashSet::new();
    for line in out.stdout.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let o: serde_json::Value = serde_json::from_slice(line).unwrap();
        rows.insert((
            o["path"].as_str().unwrap().to_string(),
            o["line"].as_u64().unwrap(),
            o["text"].as_str().unwrap().to_string(),
        ));
    }
    let mut rows: Vec<_> = rows.into_iter().collect();
    rows.sort();
    rows
}

#[test]
fn indexed_equals_scan() {
    let dir = fixture();
    let idx = dir.join("t.idx.json");
    let st = Command::new(bin())
        .args(["index", ".", "--index"])
        .arg(&idx)
        .current_dir(&dir)
        .status()
        .unwrap();
    assert!(st.success());
    for q in [
        "NEEDLE_ALPHA",
        "needle_1|NEEDLE_ALPHA",
        "config",
        "(?i)needle_alpha",
        "(?P<word>NEEDLE_ALPHA)",
        "NEEDLE_[A-Z]{2,}",
    ] {
        let scan = run(&["--", q, "."], &dir);
        let idx_args = [
            "--use-index".to_string(),
            idx.to_string_lossy().into_owned(),
            "--".to_string(),
            q.to_string(),
            ".".to_string(),
        ];
        // index stores paths under the root it was built with; build used "."
        // from dir, query the same way
        let got = run(
            &idx_args.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            &dir,
        );
        assert!(!scan.is_empty(), "scan found nothing for {q}");
        assert_eq!(scan, got, "divergence on {q}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// MatchFlags oracle: every matcher flag must keep indexed==scan set-equal.
/// Each case runs the scan shape and the --use-index shape and compares
/// (path, line, text) sets. Empty-expectation cases assert both sides empty.
#[test]
fn flag_matrix_equals_scan() {
    let dir = fixture_in("flags");
    // -f pattern files live beside the fixture and must predate the index
    // build, or indexed (stale snapshot) and scan (live walk) diverge.
    let pats = dir.join("pats.txt");
    std::fs::write(&pats, "NEEDLE_ALPHA\nneedle_1\n").unwrap();
    let empty_pats = dir.join("empty.txt");
    std::fs::write(&empty_pats, "").unwrap();
    let idx = dir.join("t.idx.json");
    let st = Command::new(bin())
        .args(["index", ".", "--index"])
        .arg(&idx)
        .current_dir(&dir)
        .status()
        .unwrap();
    assert!(st.success());
    let pats_s = pats.to_string_lossy().into_owned();
    let empty_s = empty_pats.to_string_lossy().into_owned();
    let idx_s = idx.to_string_lossy().into_owned();
    // (name, scan args, indexed args, expect_nonempty)
    let cases: Vec<(&str, Vec<String>, Vec<String>, bool)> = vec![
        (
            "fixed",
            svec(["-F", "--", "needle_1", "."]),
            idxv(&idx_s, ["-F", "--", "needle_1", "."]),
            true,
        ),
        (
            "fixed-pipe-literal",
            svec(["-F", "--", "needle_1|NEEDLE_ALPHA", "."]),
            idxv(&idx_s, ["-F", "--", "needle_1|NEEDLE_ALPHA", "."]),
            false,
        ),
        (
            "regex-pipe",
            svec(["--", "needle_1|NEEDLE_ALPHA", "."]),
            idxv(&idx_s, ["--", "needle_1|NEEDLE_ALPHA", "."]),
            true,
        ),
        (
            "invert",
            svec(["-v", "--", "NEEDLE_ALPHA", "."]),
            idxv(&idx_s, ["-v", "--", "NEEDLE_ALPHA", "."]),
            true,
        ),
        (
            "invert-max",
            svec(["-v", "-m1", "--", "NEEDLE_ALPHA", "."]),
            idxv(&idx_s, ["-v", "-m1", "--", "NEEDLE_ALPHA", "."]),
            true,
        ),
        (
            "word",
            svec(["-w", "--", "needle_1", "."]),
            idxv(&idx_s, ["-w", "--", "needle_1", "."]),
            true,
        ),
        (
            "word-underscore",
            svec(["-w", "--", "needle", "."]),
            idxv(&idx_s, ["-w", "--", "needle", "."]),
            false,
        ),
        (
            "word-fixed",
            svec(["-F", "-w", "--", "needle_1", "."]),
            idxv(&idx_s, ["-F", "-w", "--", "needle_1", "."]),
            true,
        ),
        (
            "word-ignorecase",
            svec(["-i", "-w", "--", "needle_alpha", "."]),
            idxv(&idx_s, ["-i", "-w", "--", "needle_alpha", "."]),
            true,
        ),
        (
            "max",
            svec(["-m2", "--", "config", "."]),
            idxv(&idx_s, ["-m2", "--", "config", "."]),
            true,
        ),
        (
            "max-zero",
            svec(["-m0", "--", "config", "."]),
            idxv(&idx_s, ["-m0", "--", "config", "."]),
            false,
        ),
        (
            "max-long",
            svec(["--max-count=1", "--", "config", "."]),
            idxv(&idx_s, ["--max-count=1", "--", "config", "."]),
            true,
        ),
        (
            "repeat-e",
            svec(["-e", "NEEDLE_ALPHA", "-e", "needle_1", "."]),
            idxv(&idx_s, ["-e", "NEEDLE_ALPHA", "-e", "needle_1", "."]),
            true,
        ),
        (
            "empty-e",
            svec(["-e", "", "."]),
            idxv(&idx_s, ["-e", "", "."]),
            true,
        ),
        (
            "file",
            svec(["-f", pats_s.as_str(), "."]),
            idxv(&idx_s, ["-f", pats_s.as_str(), "."]),
            true,
        ),
        (
            "file-empty",
            svec(["-f", empty_s.as_str(), "."]),
            idxv(&idx_s, ["-f", empty_s.as_str(), "."]),
            false,
        ),
        (
            "fixed-file",
            svec(["-F", "-f", pats_s.as_str(), "."]),
            idxv(&idx_s, ["-F", "-f", pats_s.as_str(), "."]),
            true,
        ),
        (
            "combo-all",
            svec(["-F", "-w", "-m1", "-e", "needle_1", "-e", "config", "."]),
            idxv(
                &idx_s,
                ["-F", "-w", "-m1", "-e", "needle_1", "-e", "config", "."],
            ),
            true,
        ),
    ];
    for (name, scan_args, idx_args, nonempty) in &cases {
        let scan = run(
            &scan_args.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            &dir,
        );
        let got = run(
            &idx_args.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            &dir,
        );
        assert_eq!(scan.is_empty(), !nonempty, "scan empty mismatch on {name}");
        assert_eq!(scan, got, "indexed/scan divergence on {name}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn run_raw(args: &[&str], cwd: &PathBuf) -> Vec<u8> {
    let out = Command::new(bin())
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap();
    assert!([0, 1].contains(&out.status.code().unwrap()));
    out.stdout
}

/// --top oracle: indexed top-k must equal scan top-k as sets, over small k
/// (early exit), a k past the tie boundary, and a k larger than the hit
/// count. `config` hits every line so ties dominate; NEEDLE_ALPHA is sparse.
#[test]
fn top_k_equals_scan() {
    let dir = fixture_in("topk");
    let idx = dir.join("t.idx.json");
    let st = Command::new(bin())
        .args(["index", ".", "--index"])
        .arg(&idx)
        .current_dir(&dir)
        .status()
        .unwrap();
    assert!(st.success());
    let idx_s = idx.to_string_lossy().into_owned();
    // (name, extra args, query); --top truncates rank order, sets stay equal
    // on both sides even across score ties.
    let cases: Vec<(&str, &[&str], &str)> = vec![
        ("top1-dense", &["--top", "1"], "config"),
        ("top5-dense", &["--top", "5"], "config"),
        ("top7-sparse", &["--top", "7"], "NEEDLE_ALPHA"),
        ("top-huge", &["--top", "100000"], "needle_1"),
        ("top1-word", &["--top", "1", "-w"], "needle_1"),
    ];
    for (name, extra, q) in &cases {
        let mut scan_args: Vec<&str> = extra.to_vec();
        scan_args.extend(["--", q, "."]);
        let scan = run(&scan_args, &dir);
        let mut idx_args: Vec<String> = vec!["--use-index".to_string(), idx_s.clone()];
        idx_args.extend(extra.iter().map(|s| s.to_string()));
        idx_args.extend(["--".to_string(), q.to_string(), ".".to_string()]);
        let got = run(
            &idx_args.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            &dir,
        );
        assert!(!scan.is_empty(), "scan found nothing for {name}");
        assert_eq!(scan, got, "indexed/scan --top divergence on {name}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Output-shaping oracle: -c and -l render byte-identical stdout indexed vs
/// scan (same rows, same path-sorted order).
#[test]
fn aggregates_equal_scan() {
    let dir = fixture_in("aggs");
    let idx = dir.join("t.idx.json");
    let st = Command::new(bin())
        .args(["index", ".", "--index"])
        .arg(&idx)
        .current_dir(&dir)
        .status()
        .unwrap();
    assert!(st.success());
    let idx_s = idx.to_string_lossy().into_owned();
    let cases: Vec<(&str, &[&str])> = vec![
        ("count", &["-c", "--", "NEEDLE_ALPHA", "."]),
        ("files", &["-l", "--", "needle_1", "."]),
        ("count-top", &["-c", "--top", "5", "--", "config", "."]),
    ];
    for (name, rest) in &cases {
        let scan = run_raw(rest, &dir);
        let mut idx_args: Vec<String> = vec!["--use-index".to_string(), idx_s.clone()];
        idx_args.extend(rest.iter().map(|s| s.to_string()));
        let got = run_raw(
            &idx_args.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            &dir,
        );
        assert!(!scan.is_empty(), "scan rendered nothing for {name}");
        assert_eq!(scan, got, "indexed/scan output divergence on {name}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--` ends the flag scan: everything after it is a positional, even when it
/// looks like a flag (`--top`, `-l`).
#[test]
fn dashdash_ends_flag_scan() {
    let dir = fixture_in("dashdash");
    std::fs::write(dir.join("a.txt"), "--top\n-l\nother\n").unwrap();
    for pat in ["--top", "-l"] {
        let out = Command::new(bin())
            .args(["--", pat, "."])
            .current_dir(&dir)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "exit for {pat}");
        let text = String::from_utf8(out.stdout).unwrap();
        let got: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(got["text"].as_str().unwrap(), pat);
    }
    // Flags before `--` still apply: -l lists the file, not the flag letter.
    let out = Command::new(bin())
        .args(["-l", "--", "-l", "."])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8(out.stdout).unwrap().contains("a.txt"));
    let _ = std::fs::remove_dir_all(&dir);
}

fn svec<const N: usize>(a: [&str; N]) -> Vec<String> {
    a.into_iter().map(|s| s.to_string()).collect()
}

fn idxv<const N: usize>(idx: &str, rest: [&str; N]) -> Vec<String> {
    let mut v = vec!["--use-index".to_string(), idx.to_string()];
    v.extend(rest.into_iter().map(|s| s.to_string()));
    v
}

/// Rebuild-self-exclusion: an index file living inside its own corpus must
/// not index itself — a rebuild must list the same files as the first build
/// and indexed queries must equal scan queries on both generations.
#[test]
fn rebuild_in_corpus_excludes_itself() {
    let dir = fixture_in("rebuild-self");
    let idx = dir.join("nkg.idx.json");
    let idx_s = idx.to_string_lossy().into_owned();
    for _ in 0..2 {
        let st = Command::new(bin())
            .args(["index", ".", "--index"])
            .arg(&idx)
            .current_dir(&dir)
            .status()
            .unwrap();
        assert!(st.success());
    }
    let data = std::fs::read_to_string(&idx).unwrap();
    let v: serde_json::Value = serde_json::from_str(&data).unwrap();
    let files: Vec<&str> = v["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap())
        .collect();
    assert!(
        !files.iter().any(|f| f.ends_with("nkg.idx.json")),
        "index contains itself: {files:?}"
    );
    for q in ["NEEDLE_ALPHA", "config"] {
        let scan = run(&["--", q, "."], &dir);
        let got = run(&["--use-index", &idx_s, "--", q, "."], &dir);
        assert!(!scan.is_empty(), "scan found nothing for {q}");
        assert_eq!(scan, got, "rebuild divergence on {q}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Loud I/O errors (unix): a permission-denied directory fails the index
/// build with exit 2 and no index written; an unreadable file fails both the
/// index build and a query with exit 2 instead of silently dropping from one
/// side (a build that skipped it would return fewer indexed hits with exit 0
/// where scan exits 2). Permissions are restored before cleanup so the temp
/// dir always removes.
#[cfg(unix)]
#[test]
fn loud_io_errors() {
    use std::os::unix::fs::PermissionsExt;
    let dir = fixture_in("loud-io");
    // Denied directory: index build must exit 2 with no index written.
    let denied = dir.join("denied");
    std::fs::create_dir(&denied).unwrap();
    std::fs::write(denied.join("s.txt"), "secret NEEDLE_ALPHA\n").unwrap();
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o000)).unwrap();
    let idx = dir.join("o.idx.json");
    let st = Command::new(bin())
        .args(["index", ".", "--index"])
        .arg(&idx)
        .current_dir(&dir)
        .status()
        .unwrap();
    assert_eq!(st.code(), Some(2), "denied-dir build must exit 2");
    assert!(!idx.exists(), "partial index must not be written");
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o755)).unwrap();
    // Unreadable file: scan query must exit 2. Root bypasses permission
    // bits, so skip when the file stays readable (e.g. CI as root).
    let locked = dir.join("locked.txt");
    std::fs::write(&locked, "locked NEEDLE_ALPHA\n").unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&locked).is_ok() {
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    let out = Command::new(bin())
        .args(["index", ".", "--index"])
        .arg(&idx)
        .current_dir(&dir)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "unreadable-file build must exit 2"
    );
    assert!(!idx.exists(), "partial index must not be written");
    let out = Command::new(bin())
        .args(["--", "NEEDLE_ALPHA", "."])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "unreadable-file query must exit 2"
    );
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Daemon verify I/O errors (unix): an unreadable corpus file must surface
/// as client exit 2 with readable hits still printed, not a silent empty
/// response.
#[cfg(unix)]
#[test]
fn daemon_verify_io_error_exits_2() {
    use std::os::unix::fs::PermissionsExt;
    let dir = fixture_in("daemon-io-err");
    let idx = dir.join("d.idx.json");
    let st = Command::new(bin())
        .args(["index", ".", "--index"])
        .arg(&idx)
        .current_dir(&dir)
        .status()
        .unwrap();
    assert_eq!(st.code(), Some(0));
    let locked = dir.join("pkg_0").join("m_0.txt");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&locked).is_ok() {
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    use std::process::Stdio;
    let mut srv = Command::new(bin())
        .args(["serve", "--index"])
        .arg(&idx)
        .args(["--port"])
        .arg(port.to_string())
        .current_dir(&dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut ready = false;
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            ready = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(ready, "daemon did not bind");
    let out = Command::new(bin())
        .args(["--port", &port.to_string(), "--", "NEEDLE_ALPHA", "."])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "daemon client must exit 2");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("NEEDLE_ALPHA"),
        "readable hits still printed"
    );
    srv.kill().ok();
    srv.wait().ok();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Request-scoped verify latch (unix): two concurrent daemon clients must not
/// cross-attribute I/O errors. The error client's drain must not steal the
/// clean client's flag (false exit 2) nor vice versa (false clean done).
/// The locked file holds a unique marker so only the error query verifies it;
/// a barrier (no sleeps) forces the two requests to overlap inside the
/// daemon, repeated in a tight loop so a global latch flakes reliably.
#[cfg(unix)]
#[test]
fn daemon_verify_latch_is_request_scoped() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Stdio;
    use std::sync::{Arc, Barrier};
    let dir = fixture_in("daemon-latch-scope");
    // Unique marker lives only in the locked file: NEEDLE_ALPHA queries never
    // verify it, ZZZ queries always do.
    let locked = dir.join("pkg_0").join("m_0.txt");
    std::fs::write(&locked, "ZZZ_BAD_FILE marker line\n").unwrap();
    let idx = dir.join("d.idx.json");
    let st = Command::new(bin())
        .args(["index", ".", "--index"])
        .arg(&idx)
        .current_dir(&dir)
        .status()
        .unwrap();
    assert_eq!(st.code(), Some(0));
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&locked).is_ok() {
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let mut srv = Command::new(bin())
        .args(["serve", "--index"])
        .arg(&idx)
        .args(["--port"])
        .arg(port.to_string())
        .current_dir(&dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut ready = false;
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            ready = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(ready, "daemon did not bind");
    // Baseline clean rows while the bad file is locked: single client, exit 0.
    let base = Command::new(bin())
        .args(["--port", &port.to_string(), "--", "NEEDLE_ALPHA", "."])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert_eq!(base.status.code(), Some(0), "clean query must exit 0");
    assert!(
        String::from_utf8_lossy(&base.stdout).contains("NEEDLE_ALPHA"),
        "clean query must print rows"
    );
    let port_s = port.to_string();
    let dir_a = Arc::new(dir);
    for _ in 0..20 {
        let barrier = Arc::new(Barrier::new(2));
        let run_one = |b: Arc<Barrier>, pat: &'static str| {
            let d = Arc::clone(&dir_a);
            let p = port_s.clone();
            std::thread::spawn(move || {
                b.wait();
                Command::new(bin())
                    .args(["--port", &p, "--", pat, "."])
                    .current_dir(&*d)
                    .output()
                    .unwrap()
            })
        };
        let eb = Arc::clone(&barrier);
        let cb = Arc::clone(&barrier);
        let eh = run_one(eb, "ZZZ_BAD_FILE");
        let ch = run_one(cb, "NEEDLE_ALPHA");
        let eout = eh.join().unwrap();
        let cout = ch.join().unwrap();
        assert_eq!(eout.status.code(), Some(2), "error client must exit 2");
        assert_eq!(cout.status.code(), Some(0), "clean client must exit 0");
        assert_eq!(cout.stdout, base.stdout, "clean rows must be unaffected");
    }
    srv.kill().ok();
    srv.wait().ok();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();
    let _ = std::fs::remove_dir_all(&*dir_a);
}

/// Daemon subtree oracle: `nkg --port P -- NEEDLE subdir` set-equals cold scan.
#[test]
fn daemon_subtree_equals_scan() {
    use std::net::TcpListener;
    let dir = fixture_in("daemon-sub");
    let idx = dir.join("t.idx.json");
    assert!(Command::new(bin())
        .args(["index", ".", "--index"])
        .arg(&idx)
        .current_dir(&dir)
        .status()
        .unwrap()
        .success());
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let want = listener.local_addr().unwrap().port();
    drop(listener);
    let mut srv = Command::new(bin())
        .args(["serve", "--index"])
        .arg(&idx)
        .args(["--port", &want.to_string()])
        .current_dir(&dir)
        .spawn()
        .unwrap();
    // Wait for listener.
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", want)).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    // Cold scan of subtree pkg_1 (absolute root: the live-repro'd shape).
    let sub_abs = dir.join("pkg_1").to_string_lossy().into_owned();
    let scan = run(&["--", "NEEDLE_ALPHA", &sub_abs], &dir);
    assert!(!scan.is_empty());
    // Daemon query over the absolute subtree, plus the relative form.
    let out = Command::new(bin())
        .args(["--port", &want.to_string(), "--", "NEEDLE_ALPHA", &sub_abs])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!([0, 1].contains(&out.status.code().unwrap()));
    let mut rows = std::collections::HashSet::new();
    for line in out.stdout.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let o: serde_json::Value = serde_json::from_slice(line).unwrap();
        rows.insert((
            o["path"].as_str().unwrap().to_string(),
            o["line"].as_u64().unwrap(),
            o["text"].as_str().unwrap().to_string(),
        ));
    }
    let mut rows: Vec<_> = rows.into_iter().collect();
    rows.sort();
    assert_eq!(scan, rows, "daemon subtree must set-equal cold scan");
    // Relative subtree form must agree as well.
    let out = Command::new(bin())
        .args(["--port", &want.to_string(), "--", "NEEDLE_ALPHA", "pkg_1"])
        .current_dir(&dir)
        .output()
        .unwrap();
    let mut rel = std::collections::HashSet::new();
    for line in out.stdout.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let o: serde_json::Value = serde_json::from_slice(line).unwrap();
        rel.insert((
            o["path"].as_str().unwrap().to_string(),
            o["line"].as_u64().unwrap(),
            o["text"].as_str().unwrap().to_string(),
        ));
    }
    let mut rel: Vec<_> = rel.into_iter().collect();
    rel.sort();
    let scan_rel = run(&["--", "NEEDLE_ALPHA", "pkg_1"], &dir);
    assert_eq!(
        scan_rel, rel,
        "daemon relative subtree must set-equal cold scan"
    );
    srv.kill().ok();
    srv.wait().ok();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Piped stdin with --port is a usage error (exit 2); without --port it
/// searches stdin (exit 0). Guards silent daemon-corpus search on pipes.
#[test]
fn piped_stdin_with_port_is_usage_error() {
    use std::io::Write;
    use std::process::Stdio;
    let dir = fixture();
    // Without --port: stdin search, exit 0.
    let mut kid = Command::new(bin())
        .args(["--", "marker"])
        .current_dir(&dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    kid.stdin
        .take()
        .unwrap()
        .write_all(b"marker here\n")
        .unwrap();
    let out = kid.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    // With --port: usage error, exit 2.
    let mut kid = Command::new(bin())
        .args(["--port", "1", "--", "marker"])
        .current_dir(&dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The child may exit before reading: ignore EPIPE, exit code is the assert.
    let _ = kid.stdin.take().unwrap().write_all(b"marker here\n");
    let out = kid.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("stdin search cannot use --port"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}
