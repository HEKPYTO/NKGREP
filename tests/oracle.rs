//! ONE oracle check: indexed full search must equal scan full search on a
//! planted fixture, including an alternation query. Fails on any divergence.
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_nkgrep"))
}

fn fixture() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("nkgrep-oracle-{}", std::process::id()));
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
