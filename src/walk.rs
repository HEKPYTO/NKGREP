use crate::cli::usage;
use ignore::overrides::OverrideBuilder;
use ignore::WalkBuilder;
use std::path::PathBuf;

/// Canonical absolute fingerprint of a build/query root; exit 2 when the
/// root does not resolve.
pub(crate) fn canon_root(root: &std::path::Path) -> PathBuf {
    match std::fs::canonicalize(root) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("nkg: bad root {}: {e}", root.display());
            std::process::exit(2);
        }
    }
}

/// Stable (device, inode) cookie for a canonical root; (0, 0) where the
/// platform offers no file identity (non-unix) or metadata is unreadable.
/// Unlike mtime this never changes when files are added inside the tree.
pub(crate) fn root_cookie(canon: &std::path::Path) -> (u64, u64) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match std::fs::metadata(canon) {
            Ok(m) => (m.dev(), m.ino()),
            Err(_) => (0, 0),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = canon;
        (0, 0)
    }
}

/// Traversal filters (rg-compatible shapes): `--hidden`, `--no-ignore`,
/// `-L/--follow`, `-g/--glob`, `-d/--max-depth`, `--max-filesize`.
/// Default holds historical behavior: hidden skipped, ignore files
/// respected, links unfollowed, unbounded depth/size, no globs.
#[derive(Default)]
pub(crate) struct WalkOptions {
    pub(crate) hidden: bool,
    pub(crate) no_ignore: bool,
    pub(crate) follow: bool,
    pub(crate) max_depth: Option<usize>,
    pub(crate) max_filesize: Option<u64>,
    pub(crate) globs: Vec<String>,
}

/// Loud refusal for an unparsable `--max-filesize` value (exit 2 via
/// `usage`): keeps the long `eprintln!` at a shallow indent so it fits on
/// one line under every rustfmt version; stderr bytes are unchanged.
pub(crate) fn refuse_bad_filesize(arg: &str) -> ! {
    eprintln!("nkg: bad --max-filesize {arg:?}: expected bytes with optional K/M/G suffix");
    usage();
}

/// `--max-filesize` human size: plain bytes or a K/M/G suffix (powers of
/// 1024, either case — probed live against rg 15.1.0: `1K` keeps a 1010 B
/// file). None on garbage; the caller exits 2 like rg's `invalid size`.
pub(crate) fn parse_filesize(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let (num, mult) = match s.chars().last().unwrap() {
        'K' | 'k' => (&s[..s.len() - 1], 1024u64),
        'M' | 'm' => (&s[..s.len() - 1], 1024 * 1024),
        'G' | 'g' => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        c if c.is_ascii_digit() => (s, 1),
        _ => return None,
    };
    num.parse::<u64>().ok()?.checked_mul(mult)
}

pub(crate) fn walk_files(root: &PathBuf, opts: &WalkOptions) -> (Vec<PathBuf>, bool) {
    // Paths come back sorted. Two callers depend on this: the index mints file ids
    // from the returned order, and a stable score sort breaks ties BY ID, so
    // readdir order leaked into output. It is also filesystem-specific -- APFS
    // returns directory entries in insertion order and ext4 in hash order -- so the
    // same corpus ranked equal-scored files differently per filesystem. Sorting
    // here rather than at one call site keeps the index and scan walks in the same
    // order, which is what the indexed==scan oracle compares.

    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(!opts.hidden)
        .git_ignore(!opts.no_ignore)
        .ignore(!opts.no_ignore)
        .git_global(!opts.no_ignore)
        .git_exclude(!opts.no_ignore)
        .parents(true)
        .require_git(false)
        .follow_links(opts.follow);
    if let Some(d) = opts.max_depth {
        builder.max_depth(Some(d));
    }
    // -g/--glob runs in `filter_entry`, NOT `builder.overrides`: probed rg
    // 15.1.0 keeps gitignore above -g whitelists (a gitignored file matching
    // `-g '*.txt'` is still skipped), while builder-level overrides would
    // whitelist it past gitignore ("overrides have the highest precedence").
    // The walker's own ignore machinery runs first, so gitignore still wins
    // and the Override only further restricts. Same matcher, same input
    // (leading `./` stripped exactly as dir.rs feeds it): bare globs
    // whitelist, `!` globs exclude, neg-only keeps everything else, dirs
    // never prune traversal on a non-match.
    let mut glob_matcher: Option<ignore::overrides::Override> = None;
    if !opts.globs.is_empty() {
        let mut ob = OverrideBuilder::new(root);
        for g in &opts.globs {
            if let Err(e) = ob.add(g) {
                eprintln!("nkg: bad --glob {g:?}: {e}");
                std::process::exit(2);
            }
        }
        match ob.build() {
            Ok(ov) => glob_matcher = Some(ov),
            Err(e) => {
                eprintln!("nkg: bad --glob: {e}");
                std::process::exit(2);
            }
        }
    }
    // rg parity (probed 15.1.0): `.git/` never descends unless --no-ignore:
    // --hidden alone still skips it; --hidden+--no-ignore searches it. No
    // git ops involved: pure path-component prune in filter_entry. Pruning
    // the `.git` dir entry itself kills descent, so pack files cost nothing.
    let skip_git = !opts.no_ignore;
    if glob_matcher.is_some() || opts.max_filesize.is_some() || skip_git {
        let root_path = root.clone();
        let max_opt = opts.max_filesize;
        builder.filter_entry(move |e| {
            // Explicit file operands bypass traversal filters (probed rg:
            // -g, -d, hidden, and --max-filesize all still search them).
            if e.path() == root_path {
                return true;
            }
            let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if skip_git {
                // Relative to the walk root so an explicit `.git` operand
                // still searches (probed: `rg --hidden pat .git` does). A
                // plain file named `.git` (worktree pointer) is a hidden
                // file, not a tree: searched under --hidden, never pruned.
                if let Ok(rel) = e.path().strip_prefix(&root_path) {
                    let mut comps = rel.components().peekable();
                    while let Some(c) = comps.next() {
                        let last = comps.peek().is_none();
                        if c.as_os_str() == ".git" && (!last || is_dir) {
                            return false;
                        }
                    }
                }
            }
            if let Some(max) = max_opt {
                // Files only: dir metadata lengths are filesystem noise —
                // filtering them would prune whole subtrees (probed: rg
                // keeps subdir files under --max-filesize 100).
                if !is_dir && e.metadata().map(|m| m.len() > max).unwrap_or(false) {
                    return false;
                }
            }
            match &glob_matcher {
                Some(ov) => {
                    let p = e.path();
                    let rel = p.strip_prefix("./").unwrap_or(p);
                    !ov.matched(rel, is_dir).is_ignore()
                }
                None => true,
            }
        });
    }
    let mut paths: Vec<PathBuf> = vec![];
    let mut had_error = false;
    for entry in builder.build() {
        match entry {
            Ok(e) => {
                if e.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    paths.push(e.path().to_path_buf());
                }
            }
            Err(e) => {
                eprintln!("nkg: walk error: {e}");
                had_error = true;
            }
        }
    }
    paths.sort();
    (paths, had_error)
}

/// Display-path normalization (rg parity, probed 15.1.0): strip a single
/// leading `./` so `nkg pat .` prints `src/a.txt`, not `./src/a.txt`.
/// Absolute paths and bare relatives pass through untouched.
pub(crate) fn strip_dot_slash(s: &str) -> &str {
    s.strip_prefix("./").unwrap_or(s)
}

/// Identical binary-file skip on both index and verify sides (soundness):
/// a file is binary when its first 8192 bytes contain a NUL. `cmd_index`
/// and every verify path share this predicate so indexed==scan on binaries.
/// `memchr` rather than a byte loop: the scalar `iter().any` scanned the
/// same 8 KiB head of every file one byte at a time and measured 5.2 ms over
/// a 2k-file tree against 0.2 ms here — most of what separated the scan path
/// from ripgrep once the open/read cost was subtracted.
pub(crate) fn is_binary(bytes: &[u8]) -> bool {
    memchr::memchr(0, &bytes[..bytes.len().min(8192)]).is_some()
}
