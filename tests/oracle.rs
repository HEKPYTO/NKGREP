//! ONE oracle check: indexed full search must equal scan full search on a
//! planted fixture, including an alternation query. Fails on any divergence.
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;

/// One match row, as every assertion in this file compares it.
type Rows = Vec<(String, u64, String)>;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_nkg"))
}

/// Owns a spawned `nkg serve` so a failing assert cannot orphan it.
///
/// Every daemon test kills its child AFTER its asserts, so any panic used to
/// unwind straight past the teardown and leave a `nkg serve` holding its
/// index and its `.serve.json` sidecar for the life of the machine. That leak
/// is invisible to the suite -- it passes -- and it poisons the NEXT run,
/// because any `--use-index` query then silently routes through the stale
/// daemon instead of the path under test. Drop covers the unwind path; the
/// explicit `kill`/`wait` pairs stay for the success path.
struct Daemon(std::process::Child);

impl Daemon {
    fn kill(&mut self) -> std::io::Result<()> {
        self.0.kill()
    }
    fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.0.wait()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
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
    // Both on-disk formats. The binary codec is a separate encoder and
    // decoder over the same postings, so a suite that only ever builds one
    // format cannot see a divergence between them.
    let queries = [
        "NEEDLE_ALPHA",
        "needle_1|NEEDLE_ALPHA",
        "config",
        "(?i)needle_alpha",
        "(?P<word>NEEDLE_ALPHA)",
        "NEEDLE_[A-Z]{2,}",
    ];
    let mut from_json: Vec<(String, Rows)> = Vec::new();
    for ext in ["json", "bin"] {
        let idx = dir.join(format!("t.idx.{ext}"));
        let st = Command::new(bin())
            .args(["index", ".", "--index"])
            .arg(&idx)
            .current_dir(&dir)
            .status()
            .unwrap();
        assert!(st.success(), "index build failed for {ext}");
        for q in queries {
            let scan = run(&["--", q, "."], &dir);
            // index stores paths under the root it was built with; build used
            // "." from dir, query the same way
            let idx_args = [
                "--use-index".to_string(),
                idx.to_string_lossy().into_owned(),
                "--".to_string(),
                q.to_string(),
                ".".to_string(),
            ];
            let got = run(
                &idx_args.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
                &dir,
            );
            assert!(!scan.is_empty(), "scan found nothing for {q} ({ext})");
            assert_eq!(scan, got, "divergence on {q} ({ext})");
            match ext {
                "json" => from_json.push((q.to_string(), got)),
                _ => {
                    let other = &from_json.iter().find(|(k, _)| k == q).expect("json run").1;
                    assert_eq!(other, &got, "json/bin divergence on {q}");
                }
            }
        }
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
    use std::process::Stdio;
    // Retry across ports. Picking a port by binding and then dropping it is a
    // TOCTOU race: another process can take it before the daemon binds, and
    // this box runs a daemon test suite concurrently with everything else.
    // A lost port is not a failure of the behaviour under test, so try again
    // rather than waiting out a daemon that will never come up. Same pattern
    // as `spawn_daemon`.
    let mut bound = None;
    for _ in 0..5 {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let mut cand = Daemon(
            Command::new(bin())
                .args(["serve", "--index"])
                .arg(&idx)
                .args(["--port"])
                .arg(port.to_string())
                .current_dir(&dir)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        // Readiness must come from the sidecar, not a bare connect: connect
        // succeeds against WHICHEVER process holds the port, so a squatter can
        // make a dead daemon look alive and the assertions then fail on the
        // wrong thing. The sidecar records the port the daemon actually bound.
        let sidecar = serve_sidecar(&idx);
        let _ = std::fs::remove_file(&sidecar);
        if wait_for_sidecar(&sidecar, port).is_some() {
            bound = Some((cand, port));
            break;
        }
        cand.kill().ok();
        cand.wait().ok();
    }
    let (mut srv, port) = bound.expect("daemon never bound across 5 ports");
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
    let mut srv = Daemon(
        Command::new(bin())
            .args(["serve", "--index"])
            .arg(&idx)
            .args(["--port"])
            .arg(port.to_string())
            .current_dir(&dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
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
    let mut srv = Daemon(
        Command::new(bin())
            .args(["serve", "--index"])
            .arg(&idx)
            .args(["--port", &want.to_string()])
            .current_dir(&dir)
            .spawn()
            .unwrap(),
    );
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

/// Corrupt-index oracle: the serve-eligibility probe reads only the index
/// header, so a query over a truncated or garbage index must still exit 2
/// rather than silently matching nothing. Both halves of the load are covered
/// — the header-only read and the full parse behind it.
#[test]
fn corrupt_index_exits_2() {
    let dir = fixture_in("corrupt-idx");
    let idx = dir.join("t.idx.json");
    assert!(Command::new(bin())
        .args(["index", ".", "--index"])
        .arg(&idx)
        .current_dir(&dir)
        .status()
        .unwrap()
        .success());
    let good = std::fs::read(&idx).unwrap();
    let idx_s = idx.to_string_lossy().into_owned();

    // Truncated mid-`postings`: the header parses, the document does not.
    let cut = good.len() / 2;
    std::fs::write(&idx, &good[..cut]).unwrap();
    let out = Command::new(bin())
        .args(["--use-index", &idx_s, "--", "config", "."])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "truncated index must exit 2, stdout={:?}",
        String::from_utf8_lossy(&out.stdout)
    );

    // Header intact but `postings` rewritten to a non-array: the header-only
    // read succeeds, so the full parse behind it has to be the one to refuse.
    let text = String::from_utf8(good).unwrap();
    let at = text.find("\"postings\":").expect("postings key");
    let mut broken = String::with_capacity(text.len());
    broken.push_str(&text[..at]);
    broken.push_str("\"postings\":42}");
    std::fs::write(&idx, broken).unwrap();
    let out = Command::new(bin())
        .args(["--use-index", &idx_s, "--", "config", "."])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "bad postings must exit 2");

    // Not an index at all.
    std::fs::write(&idx, b"not json at all").unwrap();
    let out = Command::new(bin())
        .args(["--use-index", &idx_s, "--", "config", "."])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "garbage index must exit 2");

    // Repeated posting key: the flat loader must refuse rather than merge or
    // concatenate the two runs, either of which would hand rank an id list the
    // document never described. The binary codec refuses an out-of-order key
    // for the same reason; keep both loud.
    let dup_src = dir.join("dup.idx.json");
    assert!(Command::new(bin())
        .args(["index", ".", "--index"])
        .arg(&dup_src)
        .current_dir(&dir)
        .status()
        .unwrap()
        .success());
    let src = std::fs::read_to_string(&dup_src).unwrap();
    const OPEN: &str = "\"postings\":{";
    let at = src.find(OPEN).expect("postings object") + OPEN.len();
    let key_end = at + src[at..].find(':').expect("first posting key");
    // The key token including its quotes, repeated empty just ahead of itself.
    let key_tok = src[at..key_end].to_string();
    std::fs::write(&idx, format!("{}{key_tok}:[],{}", &src[..at], &src[at..])).unwrap();
    let out = Command::new(bin())
        .args(["--use-index", &idx_s, "--", "config", "."])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "duplicate posting key must exit 2"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Binary-index id validation (unix): a run whose stored maximum id points
/// past the end of the file table must be refused at load with exit 2. The
/// loader reads that one value per run (ids ascend inside a run, so it is the
/// run's maximum) rather than decoding every delta, and a hostile run whose
/// stored maximum is fine but whose deltas are not is caught at decode.
#[test]
fn corrupt_binary_id_exits_2() {
    let dir = fixture_in("corrupt-bin");
    let idx = dir.join("t.idx.bin");
    assert!(Command::new(bin())
        .args(["index", ".", "--index"])
        .arg(&idx)
        .current_dir(&dir)
        .status()
        .unwrap()
        .success());
    let idx_s = idx.to_string_lossy().into_owned();
    let clean = Command::new(bin())
        .args(["--use-index", &idx_s, "--", "NEEDLE_ALPHA", "."])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert_eq!(
        clean.status.code(),
        Some(0),
        "clean binary index must query"
    );

    // magic(8) | dev(8) | ino(8) | root_len(4)+root | nfiles(4) | (len(4)+name)* | npost(4)
    // then entries of key(4) | blen(4) | last(4) | blob_off(4) | blob[blen]
    let bytes = std::fs::read(&idx).unwrap();
    let rd = |b: &[u8], at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) as usize;
    let mut cur = 24;
    cur += 4 + rd(&bytes, cur);
    let nfiles = rd(&bytes, cur);
    cur += 4;
    for _ in 0..nfiles {
        cur += 4 + rd(&bytes, cur);
    }
    let npost = rd(&bytes, cur);
    cur += 4;
    assert!(npost > 0, "fixture produced no postings");

    let mut bad = bytes.clone();
    // NKGREP06 header is `key | blen | last | blob_off`, so `last` is the
    // third field at +8; in NKGREP05 it was the fourth at +12.
    let last_at = cur + 8;
    bad[last_at..last_at + 4].copy_from_slice(&((nfiles + 999) as u32).to_le_bytes());
    std::fs::write(&idx, &bad).unwrap();
    let out = Command::new(bin())
        .args(["--use-index", &idx_s, "--", "NEEDLE_ALPHA", "."])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "out-of-range stored run maximum must exit 2 at load"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Decode-time id guard (unix): the load-time check only reads each run's
/// stored maximum, so a run whose stored maximum is valid but whose delta
/// stream does not hold that many ids must still be refused. NKGREP06 dropped
/// the id count, so the id total is derived from `blen`. Note this now fires
/// at LOAD, not at decode: an oversized `blen` makes `blob_off + blen` exceed
/// the file, which `parse_index_bin` refuses before a decode loop ever runs.
/// So it pins the extent bound, and the decode path it used to pin is gone with
/// the count field. `corrupt_header_bounds_exit_2_at_load` covers the same
/// bound from the blob-offset side.
#[test]
fn corrupt_binary_blen_exits_2() {
    let dir = fixture_in("corrupt-blen");
    std::fs::create_dir_all(dir.join("pkg_0").join("sub")).unwrap();
    std::fs::write(
        dir.join("pkg_0").join("sub").join("s.txt"),
        "config sub line\n",
    )
    .unwrap();
    let idx = dir.join("t.idx.bin");
    assert!(Command::new(bin())
        .args(["index", ".", "--index"])
        .arg(&idx)
        .current_dir(&dir)
        .status()
        .unwrap()
        .success());
    let idx_s = idx.to_string_lossy().into_owned();
    let clean = Command::new(bin())
        .args(["--use-index", &idx_s, "--", "config", "."])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert_eq!(
        clean.status.code(),
        Some(0),
        "clean binary index must query"
    );

    let bytes = std::fs::read(&idx).unwrap();
    let rd = |b: &[u8], at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) as usize;
    let mut cur = 24;
    cur += 4 + rd(&bytes, cur);
    let nfiles = rd(&bytes, cur);
    cur += 4;
    for _ in 0..nfiles {
        cur += 4 + rd(&bytes, cur);
    }
    let npost = rd(&bytes, cur);
    cur += 4;
    // NKGREP06: the header table is contiguous and fixed-stride (16 B), so
    // entry `i`'s blen sits at `hdr + i*16 + 4` with no prefix sum to walk.
    // NKGREP05 stored an id count in that field; the count is now derived from
    // the byte extent, so an absurd value there is a blob-length claim and the
    // load-time bounds check is what has to catch it.
    let hdr = cur;

    let mut bad = bytes.clone();
    for i in 0..npost {
        let p = hdr + i * 16;
        // blen field of this entry: the run's byte extent, which is also how
        // many ids the decoder will now read.
        bad[p + 4..p + 8].copy_from_slice(&u32::MAX.to_le_bytes());
    }
    std::fs::write(&idx, &bad).unwrap();

    for root in [".", "pkg_0/sub"] {
        let out = Command::new(bin())
            .args(["--use-index", &idx_s, "--", "config", root])
            .current_dir(&dir)
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(2),
            "unreadable posting run must exit 2, not allocate or panic (root {root})"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// Stale binary format: an older magic must be refused by name, not fall
/// through to the JSON parser (which reports a confusing encoding error).
/// Asserts on stderr, not just the exit code — an exit 2 from the wrong
/// branch looks identical to one from the right branch.
#[test]
fn stale_binary_format_is_named() {
    let dir = fixture_in("stale-bin");
    let idx = dir.join("old.idx.bin");
    std::fs::write(&idx, b"NKGREP02 followed by bytes that are not json").unwrap();
    let out = Command::new(bin())
        .args([
            "--use-index",
            &idx.to_string_lossy(),
            "--",
            "NEEDLE_ALPHA",
            ".",
        ])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "stale format must exit 2");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("stale index format"),
        "must name the stale format, not fall through to the JSON parser: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Subtree oracle: an indexed query rooted below the index root must equal a
/// scan of that same subtree. This is the only shape that drops files and
/// renumbers posting ids, so it covers the branch an exact-root query skips
/// (`load_index_for_query` keeps postings untouched when the query root is
/// the index root). Inverting that guard silently breaks subtree search and
/// nothing else in this suite would fail.
#[test]
fn indexed_subtree_equals_scan() {
    let dir = fixture_in("subtree");
    let idx = dir.join("t.idx.json");
    assert!(Command::new(bin())
        .args(["index", ".", "--index"])
        .arg(&idx)
        .current_dir(&dir)
        .status()
        .unwrap()
        .success());
    let idx_s = idx.to_string_lossy().into_owned();

    for sub in ["pkg_0", "pkg_3"] {
        for q in ["config", "NEEDLE_ALPHA"] {
            let scan = run(&["--", q, sub], &dir);
            let got = run(&["--use-index", &idx_s, "--", q, sub], &dir);
            assert!(!scan.is_empty(), "scan found nothing for {sub}/{q}");
            assert_eq!(scan, got, "indexed/scan subtree divergence on {sub}/{q}");
        }
        // Top-k over a subtree: the early exit and the id remap both apply.
        for q in ["config", "NEEDLE_ALPHA"] {
            for k in ["5", "20", "60"] {
                let scan = run(&["--top", k, "--", q, sub], &dir);
                let got = run(&["--use-index", &idx_s, "--top", k, "--", q, sub], &dir);
                assert!(!scan.is_empty(), "scan found nothing for {sub}/{q} top-{k}");
                assert_eq!(scan, got, "subtree --top divergence on {sub}/{q} top-{k}");
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Top-k error scope (unix), in two halves.
///
/// Verified half, mechanism-independent: an unreadable file that the query
/// actually opens must exit 2 even under `--top`. The marker matches exactly
/// one file, so that file is always the one read and the assertion survives
/// any batch size.
///
/// Skipped half, deliberately coupled to the early exit: a candidate that
/// provably cannot reach the top k is never opened, so its I/O error goes
/// unreported. That only holds while the candidate count exceeds the batch
/// size, so it needs a query matching the whole fixture plus a file whose
/// extra depth penalty sorts it past the first batch.
#[cfg(unix)]
#[test]
fn top_k_reports_errors_only_for_files_it_opens() {
    use std::os::unix::fs::PermissionsExt;
    let dir = fixture_in("topk-io");
    let deep = dir.join("pkg_0").join("deep");
    std::fs::create_dir_all(&deep).unwrap();
    // Sole match for its own marker, flat so it ranks with its peers.
    let sole = dir.join("pkg_0").join("zz_sole.txt");
    std::fs::write(&sole, "unique zz_sole_marker_xyz line\n").unwrap();
    // Matches `config` like every fixture file, but one depth penalty lower,
    // so it sorts into a later batch than the early exit reaches.
    let below = deep.join("zz_below.txt");
    std::fs::write(&below, "below config line\nsecond config line\n").unwrap();

    let idx = dir.join("t.idx.json");
    assert!(Command::new(bin())
        .args(["index", ".", "--index"])
        .arg(&idx)
        .current_dir(&dir)
        .status()
        .unwrap()
        .success());
    let idx_s = idx.to_string_lossy().into_owned();
    let lock = |p: &std::path::Path, m: u32| {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    };
    let code = |args: &[&str]| -> i32 {
        Command::new(bin())
            .args(args)
            .current_dir(&dir)
            .output()
            .unwrap()
            .status
            .code()
            .unwrap()
    };
    // Root bypasses permission bits. Gate on a plain read so the skip decision
    // cannot depend on the code path these assertions exercise — gating on an
    // nkg full query would make breaking that path silently void the test.
    let bites = |p: &std::path::Path| std::fs::read_to_string(p).is_err();

    lock(&sole, 0o000);
    if bites(&sole) {
        assert_eq!(
            code(&[
                "--use-index",
                &idx_s,
                "--top",
                "1",
                "--",
                "zz_sole_marker_xyz",
                "."
            ]),
            2,
            "top-k must still report an error in a file it opens"
        );
        assert_eq!(
            code(&["--top", "1", "--", "zz_sole_marker_xyz", "."]),
            2,
            "scan must report it too"
        );
    }
    lock(&sole, 0o644);

    lock(&below, 0o000);
    if bites(&below) {
        assert_eq!(
            code(&["--use-index", &idx_s, "--top", "5", "--", "config", "."]),
            0,
            "top-k answers 0 when the only unreadable file ranks below the cut"
        );
        assert_eq!(
            code(&["--top", "5", "--", "config", "."]),
            2,
            "the scan path has no early exit and still reports it"
        );
    }
    lock(&below, 0o644);
    let _ = std::fs::remove_dir_all(&dir);
}

/// CRLF parity: a match on a CRLF file keeps its carriage return in the
/// emitted text, because ripgrep's line content runs to the `\n` and still
/// carries the `\r` (probed byte-for-byte on rg 15.1.0, hits and context
/// alike). Trimming it made every CRLF row differ from ripgrep — invisible on
/// an all-LF fixture, and live on real trees, where 2.1% of files are CRLF.
#[test]
fn crlf_line_keeps_carriage_return() {
    let dir = fixture_in("crlf");
    // Marker unique to this fixture: `fixture_in` already plants NEEDLE_ALPHA
    // in ~36 LF files, which would drown the two rows under test.
    std::fs::write(dir.join("win.txt"), "first\r\nCRLF_MARKER here\r\nlast\r\n").unwrap();
    std::fs::write(dir.join("unix.txt"), "first\nCRLF_MARKER here\nlast\n").unwrap();
    let idx = dir.join("t.idx.json");
    assert!(Command::new(bin())
        .args(["index", ".", "--index"])
        .arg(&idx)
        .current_dir(&dir)
        .status()
        .unwrap()
        .success());
    let idx_s = idx.to_string_lossy().into_owned();

    let scan: Vec<String> = vec!["--".into(), "CRLF_MARKER".into(), ".".into()];
    let indexed: Vec<String> = vec![
        "--use-index".into(),
        idx_s,
        "--".into(),
        "CRLF_MARKER".into(),
        ".".into(),
    ];
    for args in [&scan, &indexed] {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = Command::new(bin())
            .args(&refs)
            .current_dir(&dir)
            .output()
            .unwrap();
        assert!([0, 1].contains(&out.status.code().unwrap()), "{refs:?}");
        let text = String::from_utf8_lossy(&out.stdout);
        let mut hits = 0usize;
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            hits += 1;
            let path = v["path"].as_str().unwrap();
            let body = v["text"].as_str().unwrap();
            // The CRLF file keeps its `\r`; the LF control must not gain one.
            let want_cr = path.ends_with("win.txt");
            assert_eq!(
                body.ends_with('\r'),
                want_cr,
                "carriage return handling wrong for {path} ({refs:?}): {line}"
            );
        }
        assert_eq!(hits, 2, "one hit per file ({refs:?})");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A required trigram must appear in *every* match, so a quantifier can never
/// be read as a literal byte. `AB+C` matches `ABC`, but a run of `AB+C` would
/// demand the trigram `AB+` and silently drop the match -- a missed row, not an
/// error, which is exactly the failure the indexed==scan contract exists to
/// catch. Literal punctuation (`Result<T, E>`) is the opposite case: it IS a
/// required byte, so runs must extend across it and the rarer cross-boundary
/// trigrams narrow the candidate set. Both directions are pinned here.
#[test]
fn quantifiers_and_literal_punctuation_stay_indexed_equal_scan() {
    let dir = std::env::temp_dir().join(format!("nkg-oracle-quant-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // The text holds what the patterns match, not the patterns themselves:
    // `confi+g` needs the word "config", `AB+C` needs "ABC".
    let text = "ABC\nconfig here\ncache here\nResult<T, E> here\n\
                xResult<T,E>y\nplain marker\nno match ZZQQXX\n";
    for f in 0..6 {
        std::fs::write(dir.join(format!("q_{f}.txt")), text).unwrap();
    }
    // No-ops and non-matching cases must stay empty on BOTH sides: an empty
    // scan proves the pattern really is absent, so equality is meaningful.
    let cases = [
        ("AB+C", true),
        ("AB*C", true),
        ("AB?C", true),
        ("AB{1}C", true),
        ("confi+g", true),
        ("cach+e", true),
        ("Result<T, E>", true),
        ("Result<T,E>", true),
        ("plain.marker", true),
        ("AB+D", false),
        ("Result<X, E>", false),
    ];
    let idx = dir.join("q.idx.bin");
    let st = Command::new(bin())
        .args(["index", ".", "--index"])
        .arg(&idx)
        .current_dir(&dir)
        .status()
        .unwrap();
    assert!(st.success(), "index build failed");
    for (q, expect) in cases {
        let scan = run(&["--", q, "."], &dir);
        assert_eq!(
            !scan.is_empty(),
            expect,
            "fixture does not match the case's expectation for {q:?}"
        );
        let got = run(&["--use-index", &idx.to_string_lossy(), "--", q, "."], &dir);
        assert_eq!(scan, got, "indexed diverged from scan on {q:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The two bounds a stored index can violate that no query would otherwise
/// reach. Both must be refused at LOAD, not deferred to the query that happens
/// to name the posting, and neither may turn into an allocation or a panic:
///
/// - `root_len` is read by the serve-eligibility probe, which exists to be
///   cheap and therefore must bound it against the real file length. An
///   earlier version capped it at MAX_INDEX_BYTES, so root_len = 0xFFFF_FFFF
///   passed and asked for a 4 GiB allocation to hold a path.
/// - `blob_off` points into the blob section. NKGREP03 walked every blob at
///   load; NKGREP04 stores the offset instead, so without an explicit bounds
///   check a hostile one surfaces only inside `decode_run`, and only for a
///   posting some query names.
///
/// A `.serve.json` sidecar is present so the eligibility probe actually runs.
#[test]
fn corrupt_header_bounds_exit_2_at_load() {
    let dir = fixture_in("corrupt-bounds");
    let idx = dir.join("t.idx.bin");
    assert!(Command::new(bin())
        .args(["index", ".", "--index"])
        .arg(&idx)
        .current_dir(&dir)
        .status()
        .unwrap()
        .success());
    let good = std::fs::read(&idx).unwrap();

    let rd = |b: &[u8], at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) as usize;
    // Skip the fixed header and the file table to reach the posting count.
    let mut cur = 28 + rd(&good, 24);
    let nfiles = rd(&good, cur);
    cur += 4;
    for _ in 0..nfiles {
        cur += 4 + rd(&good, cur);
    }
    let npost = rd(&good, cur);
    cur += 4;
    assert!(npost > 0, "fixture index must have postings");

    let mut cases: Vec<(String, Vec<u8>, &str)> = Vec::new();
    let mut b = good.clone();
    b[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
    // The message matters as much as the exit: a weak bound still exits 2,
    // but only after trying to allocate 4 GiB for a path. Refusing early is
    // the behaviour under test.
    cases.push(("bad root length".to_string(), b, "bad root length"));
    let mut b = good.clone();
    // blob_off just inside the file with a blen that runs past the end: only
    // the sum bound catches this, not `blob_off > len`.
    b[cur + 12..cur + 16].copy_from_slice(&((good.len() - 4) as u32).to_le_bytes());
    // NKGREP06 puts blen in field 1, so an oversized extent is written at +4;
    // in NKGREP05 the same value went to +8 because the count occupied +4.
    b[cur + 4..cur + 8].copy_from_slice(&u32::MAX.to_le_bytes());
    cases.push(("bad posting length".to_string(), b, "bad posting length"));

    for (label, bytes, want) in cases {
        let bad = dir.join("bad.idx.bin");
        std::fs::write(&bad, &bytes).unwrap();
        // The probe only runs when a sidecar exists.
        std::fs::write(dir.join("bad.idx.bin.serve.json"), b"{}").unwrap();
        let out = Command::new(bin())
            .args(["--use-index", &bad.to_string_lossy(), "--", "config", "."])
            .current_dir(&dir)
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(2),
            "{label}: must be a loud refusal, got {:?}",
            String::from_utf8_lossy(&out.stderr)
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains(want),
            "{label}: expected {want:?} in stderr, got {err:?}"
        );
        let _ = std::fs::remove_file(dir.join("bad.idx.bin.serve.json"));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// `validate_stored_files` refuses a stored path that escapes the index root.
/// It runs on every stored path of every query, so it is written as a byte
/// scan rather than `PathBuf::from(p).components()`; these cases pin the
/// rewrite to the same verdicts the path-based version gave, and cover the
/// empty-path refusal that keeps an empty entry out of the query path.
#[test]
fn hostile_stored_paths_exit_2() {
    let dir = fixture_in("hostile-paths");
    std::fs::write(dir.join("pkg_0").join("m_0.txt"), "config needle\n").unwrap();
    let json = dir.join("t.idx.json");
    assert!(Command::new(bin())
        .args(["index", ".", "--index"])
        .arg(&json)
        .current_dir(&dir)
        .status()
        .unwrap()
        .success());
    let good = std::fs::read_to_string(&json).unwrap();
    // Splice one stored path in place of the first, leaving the rest valid so
    // the refusal can only be the path check firing.
    let marker = "\"pkg_0/";
    let at = good.find(marker).expect("stored path list");
    // Search from AFTER the opening quote, or the first hit is that quote
    // itself and the splice yields malformed JSON -- which refuses for the
    // wrong reason and would make every case below pass vacuously.
    let end = good[at + 1..]
        .find('"')
        .map(|i| at + 1 + i + 1)
        .expect("closing quote");
    // (label, spliced path, substring the refusal must name). Asserting the
    // message matters: without the path check these indexes still exit 2, but
    // for an unrelated reason -- verify reports `cannot read ... No such file`
    // for a path that escapes -- so exit code alone passes vacuously.
    let cases = [
        ("absolute", "/etc/passwd", "absolute-path index"),
        ("parent-dir", "pkg_0/../../escape.txt", "escapes root"),
        ("dot-dot alone", "..", "escapes root"),
        ("empty", "", "empty stored path"),
    ];
    for (label, hostile, want) in cases {
        let mut s = String::with_capacity(good.len() + hostile.len());
        s.push_str(&good[..at]);
        s.push('"');
        s.push_str(hostile);
        s.push('"');
        s.push_str(&good[end..]);
        std::fs::write(&json, &s).unwrap();
        let out = Command::new(bin())
            .args(["--use-index", &json.to_string_lossy(), "--", "config", "."])
            .current_dir(&dir)
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{label}: expected a loud refusal, got {err:?}"
        );
        assert!(
            err.contains(want),
            "{label}: expected {want:?} in stderr, got {err:?}"
        );
    }
    // The unmodified index must still load, so the cases above are refused for
    // the path and not because the document was left malformed.
    std::fs::write(&json, &good).unwrap();
    let out = Command::new(bin())
        .args(["--use-index", &json.to_string_lossy(), "--", "config", "."])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "clean index must still query");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Cold-vs-serve score oracle fixtures: a `corpus/` tree whose needle sits
/// at three different depths under it, so a wrong `depth` term reorders rows
/// rather than shifting every score by one constant. `pkg` carries the needle
/// in its path form so the `path_bonus` term is live on both sides too.
fn score_fixture(name: &str) -> PathBuf {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("nkg-score-{}-{name}-{n}", std::process::id()));
    for (rel, body) in [
        ("pkg/one.txt", "config needle flat\nconfig needle flat\n"),
        (
            "pkg/nested/two.txt",
            "config needle nested\nconfig needle nested\n",
        ),
        (
            "pkg/nested/deeper/three.txt",
            "config needle deeper\nconfig needle deeper\n",
        ),
        // Path-bonus arm: the query pattern appears in the path itself.
        (
            "config_pkg/four.txt",
            "config needle bonus\nconfig needle bonus\n",
        ),
        (
            "decoy/five.txt",
            "config needle decoy\nconfig needle decoy\n",
        ),
        ("decoy/six.txt", "no needle here at all\nstill nothing\n"),
    ] {
        let p = dir.join("corpus").join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }
    dir
}

/// Build `<cwd>/t.idx.bin` over `<cwd>/corpus`: the shipped bench shape, a
/// relative root operand under the cwd that owns it. `cwd` is what makes two
/// placements differ in absolute terms while the operand stays `corpus`.
fn score_index(cwd: &PathBuf) -> PathBuf {
    let idx = cwd.join("t.idx.bin");
    assert!(Command::new(bin())
        .args(["index", "corpus", "--index"])
        .arg(&idx)
        .current_dir(cwd)
        .status()
        .unwrap()
        .success());
    idx
}

/// The `<index>.serve.json` sidecar `nkg serve` writes, in the one place that
/// name is built. `PathBuf::with_extension` cannot do this job: it REPLACES an
/// extension, so `t.idx.json` yields `t.idx.bin.serve.json` -- not the file the
/// daemon writes. A cleanup built that way silently removes nothing and leaves
/// the index registered, which is exactly how a later `--use-index` arm ends up
/// routed through a daemon instead of the path under test.
fn serve_sidecar(idx: &std::path::Path) -> PathBuf {
    PathBuf::from(format!("{}.serve.json", idx.to_string_lossy()))
}

/// `{"pid":…,"port":…}` -> the bound port, or None until it parses.
fn sidecar_port(sidecar: &std::path::Path) -> Option<u16> {
    let raw = std::fs::read_to_string(sidecar).ok()?;
    Some(serde_json::from_str::<serde_json::Value>(&raw).ok()?["port"].as_u64()? as u16)
}

/// A port the kernel just handed out, released again for the daemon to take.
///
/// Dropping the listener before the child rebinds is a TOCTOU race, so this is
/// only safe behind a caller that retries. Its one caller, `spawn_daemon`,
/// is: each attempt gets a fresh port, and an attempt whose sidecar names a
/// different port is treated as lost rather than accepted.
///
/// **The race is NOT closed everywhere.** Three tests still bind an ephemeral
/// port inline and drop the listener without retrying:
/// `loud_io_errors`, `daemon_verify_latch_is_request_scoped` and
/// `daemon_subtree_equals_scan`. Each asserts readiness, so a lost port
/// surfaces as a failure rather than a pass for the wrong reason — but the
/// race is real. Route them through `spawn_daemon` when their stdio handling
/// is next touched; do not assume the class is closed.
fn ephemeral_port() -> u16 {
    let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

/// Poll until the daemon registers `sidecar`, accepting it only when it names
/// the port we asked for. `serve` writes the sidecar only AFTER `bind` has
/// succeeded, so a sidecar that arrives is proof this child got this port; one
/// naming a different port is a leftover from an earlier run and is ignored.
/// None means no claim within 2 s, which is ~100x a fixture index load.
fn wait_for_sidecar(sidecar: &std::path::Path, want: u16) -> Option<u16> {
    for _ in 0..80 {
        if let Some(p) = sidecar_port(sidecar) {
            return if p == want { Some(p) } else { None };
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    None
}

/// Spawn a daemon over `idx` and return it with the port it actually bound.
///
/// The port is chosen ephemerally but is NOT trusted. Releasing the probe
/// listener and then having the daemon rebind that number is a TOCTOU: any
/// other daemon-spawning test on a parallel cargo thread can take the port in
/// between, and the old helper returned the port it had never seen the daemon
/// use -- the caller then ran its client against a dead port and asserted on
/// the wreckage, which can pass for the wrong reason. That is a better
/// explanation for a 1-in-N flake than load, and re-running does not fix it.
///
/// So the sidecar is the authority, not the probe listener: no sidecar within
/// the deadline means this attempt is lost, and the helper kills that child
/// and takes a fresh port. `--port 0` would remove the race outright, but the
/// CLI rejects it (`if port == 0` is a usage error), and widening the shipped
/// argument parser belongs to its own change, not to a test helper.
///
/// Exhausting the attempts panics with the sidecar path, so a daemon that
/// never started at all -- an unreadable index, say -- reports that instead of
/// masquerading as a port problem.
fn spawn_daemon(idx: &PathBuf, cwd: &PathBuf) -> (Daemon, u16) {
    let sidecar = serve_sidecar(idx);
    for _ in 0..5 {
        let port = ephemeral_port();
        let _ = std::fs::remove_file(&sidecar);
        let mut srv = Daemon(
            Command::new(bin())
                .args(["serve", "--index"])
                .arg(idx)
                .args(["--port", &port.to_string()])
                .current_dir(cwd)
                .spawn()
                .unwrap(),
        );
        if let Some(bound) = wait_for_sidecar(&sidecar, port) {
            return (srv, bound);
        }
        srv.kill().ok();
        srv.wait().ok();
    }
    panic!(
        "daemon never registered {} across 5 ports -- it failed to start \
         (unreadable index?) rather than merely losing a port race",
        sidecar.display()
    );
}

/// A daemon under the phase gate, with its stderr captured to a file.
///
/// The gate is read by the process doing the work, so a served query is timed
/// inside the daemon and the CLIENT cannot enable it. That coupling is exactly
/// what the test below pins: if a later edit moved the gate to the client,
/// this file would stay empty and the test would fail instead of passing
/// quietly.
fn spawn_gated_daemon(idx: &PathBuf, cwd: &PathBuf) -> (Daemon, u16, PathBuf) {
    let sidecar = serve_sidecar(idx);
    let errpath = cwd.join("phase-daemon.err");
    for _ in 0..5 {
        let port = ephemeral_port();
        let _ = std::fs::remove_file(&sidecar);
        let err = std::fs::File::create(&errpath).unwrap();
        let mut srv = Daemon(
            Command::new(bin())
                .args(["serve", "--index"])
                .arg(idx)
                .args(["--port", &port.to_string()])
                .current_dir(cwd)
                .env("NKG_PHASE_TIMING", "1")
                .stderr(err)
                .spawn()
                .unwrap(),
        );
        if let Some(bound) = wait_for_sidecar(&sidecar, port) {
            return (srv, bound, errpath);
        }
        srv.kill().ok();
        srv.wait().ok();
    }
    panic!(
        "gated daemon never registered {} across 5 ports",
        sidecar.display()
    );
}

/// The phase probe must never reach the wire.
///
/// `ph.report()` writes to stderr; the wire carries the rows and the `done`
/// frame. Nothing structurally stops a later edit from moving that write into
/// the wire path, so the invariant is pinned here rather than left to review.
///
/// The obvious two versions of this check both pass trivially, which is why
/// there are three assertions. Comparing `2>&1` false-fails on the stderr we
/// deliberately emit, and comparing only an ungated run proves nothing. The
/// cross-check that carries weight: the row count in the phase line must
/// equal the number of hit rows on the wire, so the probe cannot drift from
/// what it claims to describe.
#[test]
fn phase_probe_never_reaches_the_wire() {
    let dir = filecount_fixture(
        "phaseprobe",
        &[
            ("a.txt", "needle a\nneedle a2\n"),
            ("sub/b.txt", "needle b\nneedle b\nneedle b2\n"),
            ("sub/deep/c.txt", "needle c\n"),
        ],
    );
    let idx = score_index(&dir);
    let (mut srv, port, errpath) = spawn_gated_daemon(&idx, &dir);
    let port_s = port.to_string();
    let served = Command::new(bin())
        .args([
            "--port", &port_s, "--format", "json", "--", "needle", "corpus",
        ])
        .current_dir(&dir)
        .output()
        .unwrap();
    // The client returns as soon as it reads the `done` frame, but the
    // daemon writes its phase line afterwards. Killing on the client's
    // return truncated that write, and a truncated line loses its `rows`
    // token -- which failed this test about one run in eight under load.
    // Wait for the line to land before tearing the daemon down.
    let phase_landed = (0..200).any(|_| {
        // A COMPLETE line, not a prefix. A half-written line already contains
        // "nkg: phase:" before it is truncated, so matching the prefix would
        // accept precisely the corrupt line this wait exists to prevent.
        // Every phase line ends with "(ms)".
        if std::fs::read_to_string(&errpath)
            .map(|s| {
                s.lines()
                    .any(|l| l.contains("nkg: phase:") && l.trim_end().ends_with("(ms)"))
            })
            .unwrap_or(false)
        {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
        false
    });
    srv.kill().ok();
    srv.wait().ok();
    let _ = std::fs::remove_file(serve_sidecar(&idx));
    assert!(
        phase_landed,
        "the gated daemon never wrote a phase line within 2s of the query returning"
    );

    let wire = String::from_utf8_lossy(&served.stdout).into_owned();
    assert!(
        !wire.contains("phase"),
        "the probe reached stdout; the wire must stay rows plus the done frame"
    );
    let hits = wire.lines().filter(|l| !l.is_empty()).count();
    assert!(
        hits >= 2,
        "fixture should produce a multi-hit wire, got {hits} lines"
    );

    let daemon_err = std::fs::read_to_string(&errpath).unwrap();
    // Exactly one, not "the first" and not "the last". An earlier query --
    // a sidecar check, an eligibility probe, a leaked daemon from a prior
    // test -- would put a second line in this file, and silently picking one
    // of them attributes the wrong phases to this wire. Same failure shape
    // as a zero-row arm being timed and reported.
    let found: Vec<&str> = daemon_err
        .lines()
        .filter(|l| l.contains("nkg: phase:"))
        .collect();
    assert_eq!(
        found.len(),
        1,
        "expected exactly 1 phase line from one query, got {}; stderr was {daemon_err:?}",
        found.len()
    );
    let line = found[0];
    // Parse defensively. A bare unwrap here panicked about one run in eight
    // whenever the line was truncated or interleaved; if it cannot be read,
    // say which line was bad rather than panicking with no context.
    let rows: u64 = line
        .split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .find(|w| w[0] == "rows")
        .and_then(|w| w[1].parse().ok())
        .unwrap_or_else(|| panic!("phase line has no parseable rows field: {line:?}"));
    // The `done` frame travels over the same socket but the CLIENT consumes
    // it, so stdout carries rows only -- one wire line per emitted row. That
    // is what makes this a real cross-check rather than a tautology: a probe
    // counting something other than emitted rows cannot pass it.
    assert_eq!(
        rows as usize, hits,
        "probe reported {rows} rows but the wire carried {hits}; the phase line must describe the response"
    );
}

/// The two outputs the oracle compares: cold indexed JSON first, then served
/// JSON for the same query over a daemon on the same index. Cold MUST run
/// before the daemon exists -- `serve` drops a `<index>.serve.json` sidecar
/// and a `--use-index` query auto-routes through any daemon it names, so a
/// cold run taken afterwards would not be cold at all.
fn cold_and_served(dir: &PathBuf, idx: &PathBuf) -> (String, String) {
    let idx_s = idx.to_string_lossy().into_owned();
    let cold = run_raw(
        &[
            "--use-index",
            &idx_s,
            "--format",
            "json",
            "--top",
            "3",
            "--",
            "config",
            "corpus",
        ],
        dir,
    );
    let (mut srv, port) = spawn_daemon(idx, dir);
    let served = run_raw(
        &[
            "--port",
            &port.to_string(),
            "--format",
            "json",
            "--top",
            "3",
            "--",
            "config",
            "corpus",
        ],
        dir,
    );
    srv.kill().ok();
    srv.wait().ok();
    let _ = std::fs::remove_file(serve_sidecar(idx));
    (
        String::from_utf8(cold).unwrap(),
        String::from_utf8(served).unwrap(),
    )
}

/// Served JSON must equal cold indexed JSON byte for byte -- scores included.
/// The existing serve oracles compare match SETS, which is why a wrong `depth`
/// term (every candidate rebased onto the daemon's absolute paths instead of
/// the client's root) survived: ordering was untouched and `--format text`
/// drops scores, so only the JSON `score` field carried the divergence.
#[test]
fn daemon_output_is_byte_identical_to_cold() {
    let dir = score_fixture("byte");
    let idx = score_index(&dir);
    let (cold, served) = cold_and_served(&dir, &idx);
    assert!(!cold.is_empty(), "fixture must match the query");
    assert_eq!(
        cold, served,
        "served JSON must equal cold indexed JSON byte for byte"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A score must not move when the corpus moves on disk. Same relative
/// invocation shape (`config corpus` from the directory that owns it), two
/// absolute placements; every byte of the output, `score` included, must
/// agree. This is the sharp form of the invariant: the depth penalty is
/// relative to the root the user named, so what must never leak in is the
/// absolute prefix of wherever the repository happens to live.
#[test]
fn scores_do_not_depend_on_corpus_location() {
    let dir = score_fixture("location");
    let deep_cwd = dir.join("x").join("y").join("z");
    copy_tree(&dir.join("corpus"), &deep_cwd.join("corpus"));
    let shallow_out = cold_and_served(&dir, &score_index(&dir));
    let deep_out = cold_and_served(&deep_cwd, &score_index(&deep_cwd));
    assert_eq!(
        shallow_out.0, deep_out.0,
        "cold scores must not depend on where the corpus lives"
    );
    assert_eq!(
        shallow_out, deep_out,
        "cold and served bytes must both be location-independent"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Same shape as `cold_and_served`, but hands back stderr as well as stdout:
/// the distinct-file count the wire scan feeds is only observable on the
/// diagnostics line, so a test of it has to read that line.
fn cold_and_served_with(
    idx: &PathBuf,
    dir: &PathBuf,
    args: &[&str],
) -> (Vec<u8>, Vec<u8>, String, String) {
    let idx_s = idx.to_string_lossy().into_owned();
    let mut cold_args: Vec<&str> = vec!["--use-index", &idx_s];
    cold_args.extend_from_slice(args);
    let cold = Command::new(bin())
        .args(&cold_args)
        .current_dir(dir)
        .output()
        .unwrap();
    let (mut srv, port) = spawn_daemon(idx, dir);
    let port_s = port.to_string();
    let mut served_args: Vec<&str> = vec!["--port", &port_s];
    served_args.extend_from_slice(args);
    let served = Command::new(bin())
        .args(&served_args)
        .current_dir(dir)
        .output()
        .unwrap();
    srv.kill().ok();
    srv.wait().ok();
    let _ = std::fs::remove_file(serve_sidecar(idx));
    assert!([0, 1].contains(&cold.status.code().unwrap()));
    assert!([0, 1].contains(&served.status.code().unwrap()));
    (
        cold.stdout,
        served.stdout,
        String::from_utf8_lossy(&cold.stderr).into_owned(),
        String::from_utf8_lossy(&served.stderr).into_owned(),
    )
}

/// Distinct paths on a served JSON wire, exactly as a client reads them.
fn wire_paths(stdout: &[u8]) -> HashSet<String> {
    stdout
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| {
            serde_json::from_slice::<serde_json::Value>(l).unwrap()["path"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect()
}

/// The `M files` figure off an `nkg: N matches in M files, …` line.
fn diag_file_count(stderr: &str) -> usize {
    stderr
        .split("matches in ")
        .nth(1)
        .expect("diagnostics line carries the file count")
        .split_whitespace()
        .next()
        .expect("file count is followed by a word")
        .parse()
        .expect("file count is a number")
}

fn filecount_fixture(name: &str, files: &[(&str, &str)]) -> PathBuf {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("nkg-filecount-{}-{name}-{n}", std::process::id()));
    for (rel, body) in files {
        let p = dir.join("corpus").join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }
    dir
}

/// The equality contract must survive LINES LONGER THAN ANY BUFFER.
///
/// Every gate-A fixture until now was short-line synthetic text, so nothing
/// exercised grep-searcher's line buffer. If a buffer silently truncated a
/// long line, indexed search would return fewer matches than scan search and
/// the tool's entire premise -- provable match-set equality with ripgrep --
/// would fail quietly on real source. Verified against ripgrep on 1310 real
/// `.rs` files (five queries, all equal); this pins it so a regression cannot
/// pass unnoticed on short fixtures alone.
///
/// Sizes straddle the usual 64 KiB searcher buffer rather than sitting under
/// it, and one file carries a multi-megabyte line.
#[test]
fn very_long_lines_preserve_indexed_equals_scan() {
    let long = |n: usize, tag: &str| {
        let mut body = String::with_capacity(n + 32);
        body.push_str(tag);
        body.push_str(&"x".repeat(n - tag.len()));
        body
    };
    let dir = filecount_fixture(
        "longline",
        &[
            // ~70 KiB: just over a 64 KiB line buffer.
            (
                "shortish.rs",
                &format!(
                    "{}\nneedle here\n{}\n",
                    long(70_000, "a"),
                    long(70_000, "b")
                ),
            ),
            // ~700 KiB: an order of magnitude past it.
            ("big.rs", &format!("needle {}\n", long(700_000, "c"))),
            // Multi-megabyte single line.
            (
                "huge.rs",
                &format!("{}\nneedle tail\n", long(3_000_000, "d")),
            ),
            // Ordinary lines alongside, so the fixture is not all edge cases.
            ("normal.rs", "needle one\nneedle two\n"),
        ],
    );
    let idx = score_index(&dir);
    // The floor is what stops this test being vacuous. Asserting only that
    // indexed == scan passes trivially if a regression drops every match in
    // BOTH paths -- 0 == 0 -- which is exactly the failure being guarded.
    for (q, floor) in [("needle", 5usize), ("needle here", 1), ("needle tail", 1)] {
        let n = run_raw(
            &["--use-index", &idx.to_string_lossy(), "--", q, "corpus"],
            &dir,
        );
        let s = run_raw(&["--", q, "corpus"], &dir);
        let nr = String::from_utf8_lossy(&n)
            .lines()
            .filter(|l| !l.is_empty())
            .count();
        let sr = String::from_utf8_lossy(&s)
            .lines()
            .filter(|l| !l.is_empty())
            .count();
        assert_eq!(nr, sr, "long-line fixture: {q:?} indexed={nr} scan={sr}");
        assert!(
            nr >= floor,
            "long-line fixture: {q:?} matched only {nr} rows, expected at least {floor}; \
             both paths lost matches, so the equality assert held vacuously"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A match TEXT carrying a whole `{"path":"corpus/ghost.txt","line":9,…}`
/// prefix must never be mistaken for the row's own path field. Both wire
/// shapes put `path` first, so the injected copy sits past the field a
/// correct scan stops at — but a scan that searched the row for the key
/// instead of anchoring at its start would report the ghost as a second
/// matching file. Cold knows its file count from verify and never sees the
/// wire at all, so this is the arm where serve and cold would diverge.
#[test]
fn serve_file_count_ignores_injected_path_prefix_in_match_text() {
    let dir = filecount_fixture(
        "inject",
        &[(
            "inject.txt",
            "needle before\nneedle {\"path\":\"corpus/ghost.txt\",\"line\":9,\"text\":\"g\",\"score\":0} after\n",
        )],
    );
    let idx = score_index(&dir);
    let (_, served, cold_err, served_err) =
        cold_and_served_with(&idx, &dir, &["--format", "json", "--", "needle", "corpus"]);
    let expected = HashSet::from(["corpus/inject.txt".to_string()]);
    assert_eq!(
        wire_paths(&served),
        expected,
        "the wire itself is the control"
    );
    assert_eq!(
        diag_file_count(&cold_err),
        1,
        "cold counts from verify: {cold_err}"
    );
    assert_eq!(
        diag_file_count(&served_err),
        1,
        "the injected row prefix must not become a counted path: {served_err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same arm without the leading brace: `"path":"corpus/ghost.txt"` in the
/// match text. Distinct from the case above because a scan keying on `"` plus
/// `path` rather than on the full `{"path":"` prefix would survive the first
/// test and fail this one.
#[test]
fn serve_file_count_ignores_bare_path_key_in_match_text() {
    let dir = filecount_fixture(
        "barekey",
        &[(
            "bare.txt",
            "needle \"path\":\"corpus/ghost.txt\" tail\nneedle plain\n",
        )],
    );
    let idx = score_index(&dir);
    let (_, served, cold_err, served_err) =
        cold_and_served_with(&idx, &dir, &["--format", "json", "--", "needle", "corpus"]);
    assert_eq!(
        wire_paths(&served),
        HashSet::from(["corpus/bare.txt".to_string()])
    );
    assert_eq!(diag_file_count(&cold_err), 1, "{cold_err}");
    assert_eq!(
        diag_file_count(&served_err),
        1,
        "a bare \"path\" key in match text must not be counted: {served_err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Distinct means distinct, and the path field is escaped. Three ways to be
/// wrong, each landing on a different number than 7:
///   `many.txt` holds twenty matching rows and must count once, not twenty;
///   `q"1.txt` / `q"2.txt` differ only AFTER an embedded quote, so a scan
///   stopping at the first `"` truncates both to `corpus/q\` and collapses
///   them into one;
///   `back\s1.txt` / `back\s2.txt` differ only after an escaped backslash, so
///   a scan that dropped the escape handling would do the same to them.
/// 27 matching rows live in 7 files.
#[test]
fn serve_file_count_deduplicates_and_survives_escaped_paths() {
    let many = "needle many\n".repeat(20);
    let dir = filecount_fixture(
        "distinct",
        &[
            ("plain.txt", "needle plain\n"),
            ("q\"1.txt", "needle q one\n"),
            ("q\"2.txt", "needle q two\n"),
            ("back\\s1.txt", "needle back one\n"),
            ("back\\s2.txt", "needle back two\n"),
            ("many.txt", many.as_str()),
            ("other.txt", "needle other\nneedle other again\n"),
        ],
    );
    let idx = score_index(&dir);
    let (_, served, cold_err, served_err) =
        cold_and_served_with(&idx, &dir, &["--format", "json", "--", "needle", "corpus"]);
    assert_eq!(
        wire_paths(&served).len(),
        7,
        "seven distinct files on the wire"
    );
    assert_eq!(
        diag_file_count(&cold_err),
        7,
        "cold counts from verify: {cold_err}"
    );
    assert_eq!(
        diag_file_count(&served_err),
        7,
        "20 rows in one file count once, and quoted/backslash paths stay \
         distinct: {served_err}"
    );
    assert!(
        cold_err.contains("27 matches in 7 files"),
        "fixture must match what the count says: {cold_err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The file count is one stderr number, but it is reached from every flag
/// shape, so byte-identity has to hold across the matrix and not just on the
/// default path: stdout equal, and the `M files` figure equal to cold's.
#[test]
fn serve_file_count_matches_cold_across_the_flag_matrix() {
    let dir = filecount_fixture(
        "matrix",
        &[
            ("a.txt", "needle a\nneedle a2\n"),
            ("sub/b.txt", "needle b\n"),
            ("q\"c.txt", "needle c\nneedle c2\nneedle c3\n"),
        ],
    );
    let idx = score_index(&dir);
    for (label, args) in [
        ("json", vec!["--format", "json", "--", "needle", "corpus"]),
        ("text", vec!["--format", "text", "--", "needle", "corpus"]),
        ("count", vec!["-c", "--", "needle", "corpus"]),
        ("files", vec!["-l", "--", "needle", "corpus"]),
        ("context", vec!["-B", "1", "--", "needle", "corpus"]),
        ("top", vec!["--top", "2", "--", "needle", "corpus"]),
    ] {
        let (cold, served, cold_err, served_err) = cold_and_served_with(&idx, &dir, &args);
        assert_eq!(cold, served, "{label}: stdout bytes must be identical");
        assert_eq!(
            diag_file_count(&cold_err),
            diag_file_count(&served_err),
            "{label}: served file count must match cold's: cold={cold_err} served={served_err}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let dst = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_tree(&e.path(), &dst);
        } else {
            std::fs::copy(e.path(), dst).unwrap();
        }
    }
}

/// `files` x `lines` files of `needle` rows under `<dir>/corpus`, sized in
/// bytes by the caller: the dribbling test below pays one syscall per byte of
/// the response, so its size is set by the batch count it needs, not by how
/// big a response can be.
fn bulk_fixture(name: &str, files: usize, lines: usize) -> PathBuf {
    let dir = filecount_fixture(name, &[]);
    std::fs::create_dir_all(dir.join("corpus")).unwrap();
    for f in 0..files {
        let mut text = String::new();
        for ln in 0..lines {
            text.push_str(&format!(
                "line {ln} needle filler words config cache token\n"
            ));
        }
        std::fs::write(dir.join("corpus").join(format!("m_{f:02}.txt")), text).unwrap();
    }
    dir
}

/// The daemon ships a response in batches rather than one buffered write, and
/// the client frames it with `read_line`. A socket that hands the client ONE
/// BYTE AT A TIME is the worst segmentation that framing has to survive, and
/// it is what makes "a batch boundary never lands mid-row" testable rather
/// than assumed. Same query twice -- direct, then dribbled -- must produce
/// the identical byte stream, and the rows must be exactly cold's.
#[test]
fn daemon_batched_response_reassembles_under_max_segmentation() {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    // Two full 64 KiB emit batches plus a tail, ~105 B/row.
    let dir = bulk_fixture("dribble", 12, 150);
    let idx = score_index(&dir);
    let idx_s = idx.to_string_lossy().into_owned();
    // Cold FIRST: `serve` drops a sidecar that would auto-route a
    // `--use-index` query through the daemon under test.
    let cold = run(
        &[
            "--use-index",
            &idx_s,
            "--format",
            "json",
            "--",
            "needle",
            "corpus",
        ],
        &dir,
    );
    assert!(!cold.is_empty(), "fixture must match");

    let (mut srv, port) = spawn_daemon(&idx, &dir);
    let port_s = port.to_string();
    let direct = Command::new(bin())
        .args([
            "--port", &port_s, "--format", "json", "--", "needle", "corpus",
        ])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert_eq!(direct.status.code(), Some(0), "served query must exit 0");
    assert!(
        direct.stdout.len() > 2 * 64 * 1024,
        "response must span more than two emit batches: {} bytes",
        direct.stdout.len()
    );

    // Proxy: the request upstream untouched, the response downstream one
    // byte at a time.
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let pport = proxy.local_addr().unwrap().port();
    let relay = std::thread::spawn(move || {
        let (mut client, _) = proxy.accept().unwrap();
        let mut daemon = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut up = client.try_clone().unwrap();
        let mut down = daemon.try_clone().unwrap();
        // Held aside so the relay can end the daemon's request stream the
        // moment the client is gone: otherwise the daemon sits in its 60 s
        // read timeout waiting for a query that will never come, and the
        // whole test waits a minute for that.
        let fin = daemon.try_clone().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = up.read(&mut buf) {
                if n == 0 || down.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            let _ = fin.shutdown(std::net::Shutdown::Write);
        });
        let mut one = [0u8; 1];
        while let Ok(n) = daemon.read(&mut one) {
            if n == 0 || client.write_all(&one).is_err() {
                break;
            }
        }
    });

    let pport_s = pport.to_string();
    let dribbled = Command::new(bin())
        .args([
            "--port", &pport_s, "--format", "json", "--", "needle", "corpus",
        ])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert_eq!(
        dribbled.status.code(),
        Some(0),
        "dribbled query must exit 0"
    );
    relay.join().unwrap();
    assert_eq!(
        dribbled.stdout, direct.stdout,
        "one-byte-at-a-time delivery must reassemble to the identical byte stream"
    );

    let mut served: Vec<(String, u64, String)> = direct
        .stdout
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| {
            let o: serde_json::Value = serde_json::from_slice(l).unwrap();
            (
                o["path"].as_str().unwrap().to_string(),
                o["line"].as_u64().unwrap(),
                o["text"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    served.sort();
    assert_eq!(
        served, cold,
        "the batches must not drop, reorder or alter a row"
    );

    srv.kill().ok();
    srv.wait().ok();
    let _ = std::fs::remove_file(serve_sidecar(&idx));
    let _ = std::fs::remove_dir_all(&dir);
}

/// `done` is the terminator every served client waits on, so it must be the
/// last line of a batched response and the only line carrying it. A client
/// that walks away mid-stream is the new failure mode batching introduces --
/// it fails a batch write instead of one big one -- so the daemon must still
/// serve the next client, identically.
#[test]
fn daemon_done_line_is_last_and_midstream_disconnect_is_survivable() {
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpStream};
    // No dribbling here, so this one is sized generously: ~1.6 MB, 25+ batches.
    let dir = bulk_fixture("done", 40, 400);
    let idx = score_index(&dir);
    let (mut srv, port) = spawn_daemon(&idx, &dir);

    // Raw wire, minimal query: rows, then `done`, then EOF.
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.write_all(br#"{"pattern":"needle"}"#).unwrap();
    s.write_all(b"\n").unwrap();
    s.shutdown(Shutdown::Write).unwrap();
    let mut wire = vec![];
    s.read_to_end(&mut wire).unwrap();
    drop(s);
    let lines: Vec<&[u8]> = wire
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .collect();
    assert!(lines.len() > 10_000, "fixture must span many batches");
    let last = String::from_utf8_lossy(lines[lines.len() - 1]).into_owned();
    assert!(
        last.starts_with(r#"{"done":true"#),
        "last line is not done: {last}"
    );
    assert_eq!(
        lines
            .iter()
            .filter(|l| String::from_utf8_lossy(l).contains(r#""done""#))
            .count(),
        1,
        "`done` must appear on exactly one line"
    );
    serde_json::from_slice::<serde_json::Value>(lines[lines.len() - 2]).unwrap();

    let port_s = port.to_string();
    let client = || {
        Command::new(bin())
            .args([
                "--port", &port_s, "--format", "json", "--", "needle", "corpus",
            ])
            .current_dir(&dir)
            .output()
            .unwrap()
    };
    let before = client();
    assert_eq!(before.status.code(), Some(0), "served query must exit 0");

    // Mid-stream disconnect: take a slice of a response, then hang up.
    let mut cut = TcpStream::connect(("127.0.0.1", port)).unwrap();
    cut.write_all(br#"{"pattern":"needle"}"#).unwrap();
    cut.write_all(b"\n").unwrap();
    let mut head = [0u8; 512];
    let _ = cut.read(&mut head);
    drop(cut);

    let after = client();
    assert_eq!(
        after.status.code(),
        Some(0),
        "daemon must still serve after a mid-stream drop"
    );
    assert_eq!(
        after.stdout, before.stdout,
        "post-disconnect response must be identical"
    );

    srv.kill().ok();
    srv.wait().ok();
    let _ = std::fs::remove_file(serve_sidecar(&idx));
    let _ = std::fs::remove_dir_all(&dir);
}
