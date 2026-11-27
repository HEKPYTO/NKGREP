use crate::cli::usage;
use ignore::overrides::OverrideBuilder;
use ignore::WalkBuilder;
use std::path::PathBuf;

pub(crate) fn canon_root(root: &std::path::Path) -> PathBuf {
    match std::fs::canonicalize(root) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("nkg: bad root {}: {e}", root.display());
            std::process::exit(2);
        }
    }
}

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

#[derive(Default)]
pub(crate) struct WalkOptions {
    pub(crate) hidden: bool,
    pub(crate) no_ignore: bool,
    pub(crate) follow: bool,
    pub(crate) max_depth: Option<usize>,
    pub(crate) max_filesize: Option<u64>,
    pub(crate) globs: Vec<String>,
}

pub(crate) fn refuse_bad_filesize(arg: &str) -> ! {
    eprintln!("nkg: bad --max-filesize {arg:?}: expected bytes with optional K/M/G suffix");
    usage();
}

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
    let skip_git = !opts.no_ignore;
    if glob_matcher.is_some() || opts.max_filesize.is_some() || skip_git {
        let root_path = root.clone();
        let max_opt = opts.max_filesize;
        builder.filter_entry(move |e| {
            if e.path() == root_path {
                return true;
            }
            let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if skip_git {
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

pub(crate) fn strip_dot_slash(s: &str) -> &str {
    s.strip_prefix("./").unwrap_or(s)
}

pub(crate) fn is_binary(bytes: &[u8]) -> bool {
    memchr::memchr(0, &bytes[..bytes.len().min(8192)]).is_some()
}
