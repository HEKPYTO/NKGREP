//! ONE oracle check: indexed full search must equal scan full search on a
//! planted fixture, including an alternation query. Fails on any divergence.
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_nkgrep"))
}

fn fixture() -> PathBuf {
    fixture_in("base")
}

fn fixture_in(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("nkgrep-oracle-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
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

fn svec<const N: usize>(a: [&str; N]) -> Vec<String> {
    a.into_iter().map(|s| s.to_string()).collect()
}

fn idxv<const N: usize>(idx: &str, rest: [&str; N]) -> Vec<String> {
    let mut v = vec!["--use-index".to_string(), idx.to_string()];
    v.extend(rest.into_iter().map(|s| s.to_string()));
    v
}
