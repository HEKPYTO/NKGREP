use crate::attach_context;
use crate::walk::is_binary;
use grep_regex::RegexMatcher;
use grep_searcher::{Searcher, SearcherBuilder, Sink, SinkMatch};
#[cfg(test)]
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
#[derive(Serialize, Deserialize, Clone)]
#[cfg(test)]
pub(crate) struct Hit {
    pub(crate) path: std::sync::Arc<String>,
    pub(crate) line: u64,
    pub(crate) text: String,
    pub(crate) score: f64,
}

pub(crate) struct HitMeta {
    pub(crate) line: u64,
    pub(crate) start: u32,
    pub(crate) end: u32,
    pub(crate) score: f64,
}

pub(crate) struct FileHits {
    pub(crate) pid: u32,
    pub(crate) arena: Vec<u8>,
    pub(crate) metas: Vec<HitMeta>,
    pub(crate) line_starts: Vec<u32>,
}

pub(crate) struct ColCollector {
    pub(crate) arena: Vec<u8>,
    pub(crate) metas: Vec<HitMeta>,
    pub(crate) path_bonus: f64,
    pub(crate) match_limit: Option<u64>,
}

impl Sink for ColCollector {
    type Error = Box<dyn std::error::Error>;

    fn matched(&mut self, _searcher: &Searcher, m: &SinkMatch<'_>) -> Result<bool, Self::Error> {
        let line_no = m.line_number().unwrap_or(1).max(1);
        let bytes = m.bytes();
        let score = self.path_bonus - (line_no as f64) / 1e6;
        let start = self.arena.len() as u32;
        self.arena.extend_from_slice(bytes);
        let end = self.arena.len() as u32;
        self.metas.push(HitMeta {
            line: line_no,
            start,
            end,
            score,
        });
        Ok(self.match_limit.is_none())
    }
}

pub(crate) struct VerifyInput<'a> {
    pub(crate) err: &'a AtomicBool,
    pub(crate) pid: u32,
    pub(crate) path: &'a str,
    pub(crate) matcher: &'a RegexMatcher,
    pub(crate) file_score: f64,
    pub(crate) before: usize,
    pub(crate) after: usize,
    pub(crate) invert: bool,
    pub(crate) follow: bool,
    pub(crate) match_limit: Option<u64>,
}

pub(crate) fn note_verify_io_error(
    err: &AtomicBool,
    path: &str,
    e: &std::io::Error,
    follow: bool,
) -> bool {
    let raced_link = !follow
        && std::fs::symlink_metadata(std::path::Path::new(path))
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
    if !raced_link {
        eprintln!("nkg: cannot read {path}: {e}");
        err.store(true, Ordering::Relaxed);
    }
    false
}
pub(crate) fn take_verify_io_error(err: &AtomicBool) -> bool {
    err.swap(false, Ordering::Relaxed)
}

pub(crate) fn verify_one_raw(
    err: &AtomicBool,
    pid: u32,
    path: &str,
    matcher: &RegexMatcher,
    file_score: f64,
    follow: bool,
    match_limit: Option<u64>,
) -> Option<FileHits> {
    verify_one_raw_ctx(VerifyInput {
        err,
        pid,
        path,
        matcher,
        file_score,
        before: 0,
        after: 0,
        invert: false,
        follow,
        match_limit,
    })
}

pub(crate) fn verify_one_raw_ctx(args: VerifyInput<'_>) -> Option<FileHits> {
    let VerifyInput {
        err,
        pid,
        path,
        matcher,
        file_score,
        before,
        after,
        invert,
        follow,
        match_limit,
    } = args;
    use std::cell::RefCell;
    thread_local! {
        static SEARCHER: RefCell<Searcher> = RefCell::new(SearcherBuilder::new().build());
        static BUF: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(64 * 1024));
    }
    let mut sink = ColCollector {
        arena: vec![],
        metas: vec![],
        path_bonus: file_score,
        match_limit,
    };
    let ok = SEARCHER.with(|s| {
        BUF.with(|b| {
            let mut buf = b.borrow_mut();
            buf.clear();
            let mut local: Option<Searcher> = None;
            let mut normal = s.borrow_mut();
            if invert || match_limit.is_some() {
                let mut b = SearcherBuilder::new();
                if invert {
                    b.invert_match(true);
                }
                if let Some(limit) = match_limit {
                    b.max_matches(Some(limit));
                }
                local = Some(b.build());
            }
            let searcher: &mut Searcher = match local.as_mut() {
                Some(inv) => inv,
                None => &mut normal,
            };
            (|| -> std::io::Result<bool> {
                use std::io::{Read, Seek, SeekFrom};
                let mut f = open_verify_file(std::path::Path::new(path), follow)?;
                let mut head = [0u8; 8192];
                let n = f.read(&mut head)?;
                if n == 0 {
                    return Ok(true);
                }
                if memchr::memchr(0, &head[..n]).is_some() {
                    return Ok(true);
                }
                if before == 0 && after == 0 {
                    f.seek(SeekFrom::Start(0))?;
                    return Ok(searcher.search_reader(matcher, &mut f, &mut sink).is_ok());
                }
                f.seek(SeekFrom::Start(0))?;
                f.read_to_end(&mut buf)?;
                Ok(searcher.search_slice(matcher, &buf, &mut sink).is_ok())
            })()
            .unwrap_or_else(|e| note_verify_io_error(err, path, &e, follow))
        })
    });
    if ok && !sink.metas.is_empty() {
        let mut fh = FileHits {
            pid,
            arena: sink.arena,
            metas: sink.metas,
            line_starts: vec![],
        };
        if before > 0 || after > 0 {
            BUF.with(|b| attach_context(&mut fh, &b.borrow()));
        }
        Some(fh)
    } else {
        None
    }
}
pub(crate) fn verify_one_raw_cached(
    err: &AtomicBool,
    pid: u32,
    path: &str,
    matcher: &RegexMatcher,
    file_score: f64,
    fdc: Option<(&FdCache, u32)>,
    follow: bool,
) -> Option<FileHits> {
    verify_one_raw_cached_ctx(CachedVerify {
        err,
        pid,
        path,
        matcher,
        file_score,
        before: 0,
        after: 0,
        fdc,
        invert: false,
        follow,
    })
}

pub(crate) struct CachedVerify<'a> {
    pub(crate) err: &'a AtomicBool,
    pub(crate) pid: u32,
    pub(crate) path: &'a str,
    pub(crate) matcher: &'a RegexMatcher,
    pub(crate) file_score: f64,
    pub(crate) before: usize,
    pub(crate) after: usize,
    pub(crate) fdc: Option<(&'a FdCache, u32)>,
    pub(crate) invert: bool,
    pub(crate) follow: bool,
}

pub(crate) fn verify_one_raw_cached_ctx(args: CachedVerify<'_>) -> Option<FileHits> {
    let CachedVerify {
        err,
        pid,
        path,
        matcher,
        file_score,
        before,
        after,
        fdc,
        invert,
        follow,
    } = args;
    use std::cell::RefCell;
    thread_local! {
        static SEARCHER: RefCell<Searcher> = RefCell::new(SearcherBuilder::new().build());
        static BUF: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(64 * 1024));
    }
    let mut sink = ColCollector {
        arena: vec![],
        metas: vec![],
        path_bonus: file_score,
        match_limit: None,
    };
    let ok = SEARCHER.with(|s| {
        BUF.with(|b| {
            let mut buf = b.borrow_mut();
            buf.clear();
            let mut local: Option<Searcher> = None;
            let mut normal = s.borrow_mut();
            if invert {
                local = Some(SearcherBuilder::new().invert_match(true).build());
            }
            let searcher: &mut Searcher = match local.as_mut() {
                Some(inv) => inv,
                None => &mut normal,
            };
            (|| -> std::io::Result<bool> {
                read_verify_bytes(fdc, path, &mut buf, false, follow)?;
                if buf.is_empty() {
                    return Ok(true);
                }
                if is_binary(&buf) {
                    return Ok(true);
                }
                Ok(searcher.search_slice(matcher, &buf, &mut sink).is_ok())
            })()
            .unwrap_or_else(|e| note_verify_io_error(err, path, &e, follow))
        })
    });
    if ok && !sink.metas.is_empty() {
        let mut fh = FileHits {
            pid,
            arena: sink.arena,
            metas: sink.metas,
            line_starts: vec![],
        };
        if before > 0 || after > 0 {
            BUF.with(|b| attach_context(&mut fh, &b.borrow()));
        }
        Some(fh)
    } else {
        None
    }
}

pub(crate) fn search_stdin_raw(buf: &[u8], matcher: &RegexMatcher) -> Option<FileHits> {
    search_stdin_raw_inv(buf, matcher, false)
}

pub(crate) fn search_stdin_raw_inv(
    buf: &[u8],
    matcher: &RegexMatcher,
    invert: bool,
) -> Option<FileHits> {
    use std::cell::RefCell;
    thread_local! {
        static SEARCHER: RefCell<Searcher> = RefCell::new(SearcherBuilder::new().build());
    }
    if buf.is_empty() {
        return None;
    }
    if is_binary(buf) {
        return None;
    }
    let mut sink = ColCollector {
        arena: vec![],
        metas: vec![],
        path_bonus: 0.0,
        match_limit: None,
    };
    let ok = SEARCHER.with(|s| {
        let mut local: Option<Searcher> = None;
        let mut normal = s.borrow_mut();
        if invert {
            local = Some(SearcherBuilder::new().invert_match(true).build());
        }
        let searcher: &mut Searcher = match local.as_mut() {
            Some(inv) => inv,
            None => &mut normal,
        };
        searcher.search_slice(matcher, buf, &mut sink).is_ok()
    });
    if ok && !sink.metas.is_empty() {
        Some(FileHits {
            pid: 0,
            arena: sink.arena,
            metas: sink.metas,
            line_starts: vec![],
        })
    } else {
        None
    }
}

#[cfg(unix)]
pub(crate) struct CachedFd {
    fd: std::os::unix::io::RawFd,
    len: u64,
    modified: std::time::SystemTime,
}

#[cfg(unix)]
impl Drop for CachedFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

pub(crate) struct FdCache {
    #[cfg(unix)]
    slots: Vec<std::sync::Mutex<Option<CachedFd>>>,
}

impl FdCache {
    pub(crate) fn new(nfiles: usize) -> Self {
        #[cfg(unix)]
        {
            let mut slots = Vec::with_capacity(nfiles);
            for _ in 0..nfiles {
                slots.push(std::sync::Mutex::new(None));
            }
            FdCache { slots }
        }
        #[cfg(not(unix))]
        {
            let _ = nfiles;
            FdCache {}
        }
    }
}

#[cfg(unix)]
pub(crate) fn bump_nofile_for_cache(want_files: usize) {
    unsafe {
        let mut lim: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim as *mut _) != 0 {
            return;
        }
        let want = (want_files as libc::rlim_t).saturating_add(128);
        if lim.rlim_cur >= want {
            return;
        }
        let mut next = lim;
        next.rlim_max = next.rlim_max.max(want);
        next.rlim_cur = want;
        if libc::setrlimit(libc::RLIMIT_NOFILE, &next as *const _) != 0 {
            next = lim;
            next.rlim_cur = next.rlim_max;
            let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &next as *const _);
        }
        let mut after: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut after as *mut _) == 0 {
            eprintln!("nkg: NOFILE cur={} max={}", after.rlim_cur, after.rlim_max);
        }
    }
}
#[cfg(not(unix))]
pub(crate) fn bump_nofile_for_cache(_want_files: usize) {}

#[cfg(unix)]
pub(crate) fn pread_all(fd: std::os::unix::io::RawFd, buf: &mut Vec<u8>) -> std::io::Result<()> {
    let mut off: libc::off_t = 0;
    loop {
        if buf.len() == buf.capacity() {
            buf.reserve(8 * 1024);
        }
        let n = unsafe {
            let dst = buf.spare_capacity_mut();
            libc::pread(fd, dst.as_mut_ptr() as *mut libc::c_void, dst.len(), off)
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            return Ok(());
        }
        let n = n as usize;
        off += n as libc::off_t;
        unsafe {
            buf.set_len(buf.len() + n);
        }
    }
}

pub(crate) fn open_verify_file(
    path: &std::path::Path,
    follow: bool,
) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut o = std::fs::OpenOptions::new();
        o.read(true);
        if !follow {
            o.custom_flags(libc::O_NOFOLLOW);
        }
        o.open(path)
    }
    #[cfg(not(unix))]
    {
        if !follow
            && std::fs::symlink_metadata(path)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "refusing symlink without -L/--follow",
            ));
        }
        std::fs::File::open(path)
    }
}
pub(crate) fn plain_open_read(path: &str, buf: &mut Vec<u8>, follow: bool) -> std::io::Result<()> {
    use std::io::Read;
    open_verify_file(std::path::Path::new(path), follow)?.read_to_end(buf)?;
    Ok(())
}

#[cfg(unix)]
pub(crate) fn read_verify_bytes(
    fdc: Option<(&FdCache, u32)>,
    path: &str,
    buf: &mut Vec<u8>,
    retried: bool,
    follow: bool,
) -> std::io::Result<()> {
    let (cache, id) = match fdc {
        None => return plain_open_read(path, buf, follow),
        Some(x) => x,
    };
    let slot = match cache.slots.get(id as usize) {
        Some(s) => s,
        None => return plain_open_read(path, buf, follow),
    };
    let hit_fd: Option<std::os::unix::io::RawFd> = 'hit: {
        let guard = slot.lock().unwrap_or_else(|e| e.into_inner());
        let e = match guard.as_ref() {
            Some(e) => e,
            None => break 'hit None,
        };
        let fm = {
            use std::os::unix::io::FromRawFd;
            let borrowed = unsafe { std::mem::ManuallyDrop::new(std::fs::File::from_raw_fd(e.fd)) };
            match borrowed.metadata() {
                Ok(m) => m,
                Err(_) => break 'hit None,
            }
        };
        use std::os::unix::fs::MetadataExt;
        if fm.len() != e.len || fm.modified().ok() != Some(e.modified) {
            break 'hit None;
        }
        let live = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return plain_open_read(path, buf, follow),
        };
        if live.dev() != fm.dev() || live.ino() != fm.ino() {
            break 'hit None;
        }
        match live.modified() {
            Ok(t) if live.len() == e.len && t == e.modified => Some(e.fd),
            Ok(_) => break 'hit None,
            Err(_) => return plain_open_read(path, buf, follow),
        }
    };
    if let Some(fd) = hit_fd {
        match pread_all(fd, buf) {
            Ok(()) => return Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::EBADF) && !retried => {
                *slot.lock().unwrap_or_else(|e| e.into_inner()) = None;
                return read_verify_bytes(fdc, path, buf, true, follow);
            }
            Err(e) => return Err(e),
        }
    }
    let f = match open_verify_file(std::path::Path::new(path), follow) {
        Ok(f) => f,
        Err(_) => return plain_open_read(path, buf, follow),
    };
    let (flen, fmod) = match f
        .metadata()
        .and_then(|m| m.modified().map(|t| (m.len(), t)))
    {
        Ok(x) => x,
        Err(_) => return plain_open_read(path, buf, follow),
    };
    let fresh = {
        use std::os::unix::io::IntoRawFd;
        f.into_raw_fd()
    };
    let fd = {
        let mut guard = slot.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(e) if e.len == flen && e.modified == fmod => {
                let fd = e.fd;
                unsafe {
                    libc::close(fresh);
                }
                fd
            }
            _ => {
                *guard = Some(CachedFd {
                    fd: fresh,
                    len: flen,
                    modified: fmod,
                });
                fresh
            }
        }
    };
    match pread_all(fd, buf) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EBADF) && !retried => {
            *slot.lock().unwrap_or_else(|e| e.into_inner()) = None;
            read_verify_bytes(fdc, path, buf, true, follow)
        }
        Err(e) => Err(e),
    }
}
#[cfg(not(unix))]
pub(crate) fn read_verify_bytes(
    _: Option<(&FdCache, u32)>,
    path: &str,
    buf: &mut Vec<u8>,
    _retried: bool,
    follow: bool,
) -> std::io::Result<()> {
    plain_open_read(path, buf, follow)
}
