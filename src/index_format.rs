use serde::{Deserialize, Serialize};
#[cfg(test)]
mod varint_tests {
    use crate::index_format::{get_varint, put_varint};

    #[test]
    fn varint_round_trips() {
        for v in [0u32, 1, 127, 128, 300, 65_535, 1 << 20, u32::MAX] {
            let mut b = Vec::new();
            put_varint(&mut b, v);
            let (got, next) = get_varint(&b, 0).expect("decodes");
            assert_eq!(got, v, "round trip for {v}");
            assert_eq!(next, b.len());
        }
    }

    #[test]
    fn varint_rejects_wider_than_u32() {
        let b = [0xffu8, 0xff, 0xff, 0xff, 0x7f, 0];
        assert!(
            get_varint(&b, 0).is_none(),
            "must refuse a value wider than u32"
        );
    }

    #[test]
    fn varint_would_not_silently_decode_to_an_in_range_id() {
        let b = [0x81u8, 0x80, 0x80, 0x80, 0x10, 0];
        assert_eq!(
            get_varint(&b, 0),
            None,
            "a wide varint must never decode to a small in-range id"
        );
        let mut u32acc: u32 = 0;
        for (i, byte) in [0x81u8, 0x80, 0x80, 0x80, 0x10].iter().enumerate() {
            u32acc |= u32::from(byte & 0x7f) << (7 * i);
        }
        assert_eq!(u32acc, 1, "the u32 form really does decode to id 1");
    }

    #[test]
    fn varint_rejects_run_past_end() {
        assert!(get_varint(&[0x80u8], 0).is_none(), "continuation past end");
        assert!(get_varint(&[], 0).is_none(), "empty buffer");
    }
}
pub(crate) enum Postings {
    Owned {
        keys: Vec<u32>,
        off: Vec<u32>,
        ids: Vec<u32>,
    },
    Raw {
        hdr: usize,
        npost: usize,
        data: std::sync::Arc<memmap2::Mmap>,
        nfiles: usize,
    },
}

impl Default for Postings {
    fn default() -> Self {
        Postings::Owned {
            keys: vec![],
            off: vec![0],
            ids: vec![],
        }
    }
}

impl Postings {
    pub(crate) fn npost(&self) -> usize {
        match self {
            Postings::Owned { keys, .. } => keys.len(),
            Postings::Raw { npost, .. } => *npost,
        }
    }
    pub(crate) fn key_at(&self, i: usize) -> u32 {
        match self {
            Postings::Owned { keys, .. } => keys[i],
            Postings::Raw { hdr, data, .. } => {
                let at = hdr + i * POSTING_HDR;
                u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
            }
        }
    }
    pub(crate) fn hdr_at(&self, i: usize, field: usize) -> u32 {
        match self {
            Postings::Owned { .. } => unreachable!("owned postings have no header table"),
            Postings::Raw { hdr, data, .. } => {
                let at = hdr + i * POSTING_HDR + field * 4;
                u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
            }
        }
    }
    pub(crate) fn find(&self, k: u32) -> Option<usize> {
        match self {
            Postings::Owned { keys, .. } => keys.binary_search(&k).ok(),
            Postings::Raw { .. } => {
                let (mut lo, mut hi) = (0usize, self.npost());
                while lo < hi {
                    let mid = lo + (hi - lo) / 2;
                    if self.key_at(mid) < k {
                        lo = mid + 1;
                    } else {
                        hi = mid;
                    }
                }
                (lo < self.npost() && self.key_at(lo) == k).then_some(lo)
            }
        }
    }
    pub(crate) fn decode_run(
        data: &[u8],
        at: usize,
        blen: usize,
        nfiles: usize,
        out: &mut Vec<u32>,
    ) {
        out.clear();
        let end = at.saturating_add(blen);
        out.reserve(blen.min(1 << 16));
        let mut prev = 0u32;
        let mut p = at;
        while p < end {
            let Some((d, next)) = get_varint(data, p) else {
                eprintln!(
                    "nkg: unreadable index (truncated posting run; rebuild with `nkg index`)"
                );
                std::process::exit(2);
            };
            p = next;
            let Some(id) = prev.checked_add(d) else {
                eprintln!("nkg: unreadable index (posting id overflow; rebuild with `nkg index`)");
                std::process::exit(2);
            };
            if id as usize >= nfiles {
                eprintln!(
                    "nkg: unreadable index (posting id out of range? rebuild with `nkg index`)"
                );
                std::process::exit(2);
            }
            prev = id;
            out.push(id);
        }
    }
    pub(crate) fn ids_at<'o>(&'o self, i: usize, out: &'o mut Vec<u32>) -> &'o [u32] {
        match self {
            Postings::Owned { off, ids, .. } => &ids[off[i] as usize..off[i + 1] as usize],
            Postings::Raw { data, nfiles, .. } => {
                let blen = self.hdr_at(i, 1) as usize;
                let blob_off = self.hdr_at(i, 3) as usize;
                Self::decode_run(data, blob_off, blen, *nfiles, out);
                out
            }
        }
    }
    pub(crate) fn into_owned(self) -> Postings {
        match self {
            owned @ Postings::Owned { .. } => owned,
            p @ Postings::Raw { .. } => {
                let Postings::Raw {
                    npost,
                    nfiles,
                    data,
                    ..
                } = &p
                else {
                    unreachable!("matched the Raw variant")
                };
                let (npost, nfiles) = (*npost, *nfiles);
                let mut keys = Vec::with_capacity(npost);
                let mut off = Vec::with_capacity(npost + 1);
                let mut ids = Vec::new();
                let mut run: Vec<u32> = Vec::new();
                off.push(0);
                for i in 0..npost {
                    let k = p.key_at(i);
                    let blen = p.hdr_at(i, 1) as usize;
                    let blob_off = p.hdr_at(i, 3) as usize;
                    Self::decode_run(data, blob_off, blen, nfiles, &mut run);
                    keys.push(k);
                    ids.extend_from_slice(&run);
                    off.push(ids.len() as u32);
                }
                Postings::Owned { keys, off, ids }
            }
        }
    }
    pub(crate) fn ids_in_range(&self, nfiles: usize) -> bool {
        match self {
            Postings::Owned { ids, .. } => ids.iter().all(|&id| (id as usize) < nfiles),
            Postings::Raw { npost, .. } => {
                (0..*npost).all(|i| (self.hdr_at(i, 2) as usize) < nfiles)
            }
        }
    }
}
impl Serialize for Postings {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let n = self.npost();
        let mut m = s.serialize_map(Some(n))?;
        let mut scratch: Vec<u32> = Vec::new();
        for i in 0..n {
            let run = self.ids_at(i, &mut scratch);
            m.serialize_entry(&self.key_at(i), run)?;
        }
        m.end()
    }
}

impl<'de> Deserialize<'de> for Postings {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_map(FlatPostingsVisitor)
    }
}

#[derive(Default)]
pub(crate) struct FlatBuild {
    entries: Vec<(u32, u32, u32)>,
    ids: Vec<u32>,
}

impl FlatBuild {
    pub(crate) fn finish(mut self) -> Result<Postings, serde::de::value::Error> {
        self.entries.sort_by_key(|e| e.0);
        let mut keys: Vec<u32> = Vec::with_capacity(self.entries.len());
        let mut off: Vec<u32> = Vec::with_capacity(self.entries.len() + 1);
        let mut ids: Vec<u32> = Vec::with_capacity(self.ids.len());
        off.push(0);
        let mut last: Option<u32> = None;
        for &(k, s, e) in &self.entries {
            if last == Some(k) {
                return Err(serde::de::Error::custom("duplicate posting key"));
            }
            keys.push(k);
            off.push(off[off.len() - 1]);
            last = Some(k);
            ids.extend_from_slice(&self.ids[s as usize..e as usize]);
            *off.last_mut().unwrap() = ids.len() as u32;
        }
        Ok(Postings::Owned { keys, off, ids })
    }
}

pub(crate) struct FlatPostingsVisitor;
impl<'de> serde::de::Visitor<'de> for FlatPostingsVisitor {
    type Value = Postings;
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a postings map")
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut m: A) -> Result<Postings, A::Error> {
        let mut b = FlatBuild::default();
        while let Some(k) = m.next_key::<u32>()? {
            m.next_value_seed(FlatRunSeed { key: k, b: &mut b })?;
        }
        b.finish().map_err(serde::de::Error::custom)
    }
}

pub(crate) struct FlatRunSeed<'a> {
    key: u32,
    b: &'a mut FlatBuild,
}
impl<'de, 'a> serde::de::DeserializeSeed<'de> for FlatRunSeed<'a> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        struct RunVisitor<'a> {
            key: u32,
            b: &'a mut FlatBuild,
        }
        impl<'de, 'a> serde::de::Visitor<'de> for RunVisitor<'a> {
            type Value = ();
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a posting id list")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
                let start = self.b.ids.len() as u32;
                self.b.ids.reserve(seq.size_hint().unwrap_or(0));
                while let Some(id) = seq.next_element::<u32>()? {
                    self.b.ids.push(id);
                }
                let end = self.b.ids.len() as u32;
                self.b.entries.push((self.key, start, end));
                Ok(())
            }
        }
        d.deserialize_seq(RunVisitor {
            key: self.key,
            b: self.b,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Index {
    pub(crate) root: String,
    pub(crate) root_dev: u64,
    pub(crate) root_ino: u64,
    pub(crate) files: Vec<String>,
    pub(crate) postings: Postings,
}

pub(crate) fn validate_stored_files(idx_path: &str, files: &[String]) {
    #[cfg(unix)]
    {
        for p in files {
            let Some(first) = p.as_bytes().first() else {
                eprintln!("nkg: unreadable index {idx_path} (empty stored path)");
                std::process::exit(2);
            };
            if *first == b'/' {
                eprintln!("nkg: stale absolute-path index {idx_path}: rebuild with `nkg index`");
                std::process::exit(2);
            }
            if p.split('/').any(|seg| seg == "..") {
                eprintln!(
                    "nkg: hostile index {idx_path} (path escapes root {p:?}): rebuild with `nkg index`"
                );
                std::process::exit(2);
            }
        }
    }
    #[cfg(not(unix))]
    {
        use std::path::{Component, PathBuf};
        for p in files {
            if p.is_empty() {
                eprintln!("nkg: unreadable index {idx_path} (empty stored path)");
                std::process::exit(2);
            }
            let path = PathBuf::from(p);
            if path.is_absolute() {
                eprintln!("nkg: stale absolute-path index {idx_path}: rebuild with `nkg index`");
                std::process::exit(2);
            }
            if path.components().any(|c| matches!(c, Component::ParentDir)) {
                eprintln!(
                    "nkg: hostile index {idx_path} (path escapes root {p:?}): rebuild with `nkg index`"
                );
                std::process::exit(2);
            }
        }
    }
}

pub(crate) fn write_index_file(idx_path: &str, bytes: &[u8]) {
    if let Ok(m) = std::fs::symlink_metadata(idx_path) {
        if m.file_type().is_symlink() {
            eprintln!("nkg: refusing to write index through symlink {idx_path}");
            std::process::exit(2);
        }
    }
    let tmp_path = format!("{idx_path}.tmp{}", std::process::id());
    {
        use std::io::Write;
        #[cfg(unix)]
        let opts = {
            use std::os::unix::fs::OpenOptionsExt;
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create(true).truncate(true);
            o.custom_flags(libc::O_NOFOLLOW);
            o
        };
        #[cfg(not(unix))]
        let opts = {
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create(true).truncate(true);
            o
        };
        let write = || -> std::io::Result<()> {
            let mut f = opts.open(&tmp_path)?;
            f.write_all(bytes)?;
            f.sync_all()
        };
        if let Err(e) = write() {
            let _ = std::fs::remove_file(&tmp_path);
            eprintln!("nkg: cannot write index {idx_path}: {e}");
            std::process::exit(2);
        }
    }
    if let Err(e) = std::fs::rename(&tmp_path, idx_path) {
        let _ = std::fs::remove_file(&tmp_path);
        eprintln!("nkg: cannot write index {idx_path}: {e}");
        std::process::exit(2);
    }
}

pub(crate) fn refuse_index(idx_path: &str, detail: &str, why: &dyn std::fmt::Display) -> ! {
    eprintln!("nkg: unreadable index {idx_path} ({detail}? rebuild with `nkg index`): {why}");
    std::process::exit(2);
}

pub(crate) fn refuse_stale_index(idx_path: &str) -> ! {
    let want = String::from_utf8_lossy(BIN_MAGIC);
    eprintln!("nkg: stale index format {idx_path} (expected {want}): rebuild with `nkg index`");
    std::process::exit(2);
}

pub(crate) fn parse_index(idx_path: &str, data: &str) -> Index {
    match serde_json::from_str::<Index>(data) {
        Ok(idx) => {
            validate_stored_files(idx_path, &idx.files);
            if !idx.postings.ids_in_range(idx.files.len()) {
                eprintln!("nkg: unreadable index {idx_path} (posting id out of range? rebuild with `nkg index`)");
                std::process::exit(2);
            }
            idx
        }
        Err(e) => refuse_index(idx_path, "old format", &e),
    }
}
pub(crate) const BIN_MAGIC: &[u8; 8] = b"NKGREP06";
pub(crate) const POSTING_HDR: usize = 16;

pub(crate) fn put_varint(out: &mut Vec<u8>, mut v: u32) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

pub(crate) fn get_varint(d: &[u8], at: usize) -> Option<(u32, usize)> {
    let mut v: u64 = 0;
    let mut shift = 0u32;
    let mut i = at;
    loop {
        let b = *d.get(i)?;
        v |= u64::from(b & 0x7f) << shift;
        if v > u64::from(u32::MAX) {
            return None;
        }
        i += 1;
        if b & 0x80 == 0 {
            return Some((v as u32, i));
        }
        shift += 7;
        if shift > 28 {
            return None;
        }
    }
}

pub(crate) fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub(crate) fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub(crate) fn encode_index_bin(idx: &Index) -> Vec<u8> {
    let mut out = Vec::with_capacity(idx.files.len() * 40);
    out.extend_from_slice(BIN_MAGIC);
    put_u64(&mut out, idx.root_dev);
    put_u64(&mut out, idx.root_ino);
    put_u32(&mut out, idx.root.len() as u32);
    out.extend_from_slice(idx.root.as_bytes());
    put_u32(&mut out, idx.files.len() as u32);
    for f in &idx.files {
        put_u32(&mut out, f.len() as u32);
        out.extend_from_slice(f.as_bytes());
    }
    let npost = idx.postings.npost();
    put_u32(&mut out, npost as u32);
    let blob_base = out.len() + npost * POSTING_HDR;
    let mut scratch: Vec<u32> = Vec::new();
    let mut run: Vec<u8> = Vec::new();
    let mut hdr: Vec<u8> = Vec::with_capacity(npost * POSTING_HDR);
    let mut blobs: Vec<u8> = Vec::new();
    for i in 0..npost {
        let ids = idx.postings.ids_at(i, &mut scratch);
        run.clear();
        let mut prev = 0u32;
        for id in ids {
            let Some(d) = id.checked_sub(prev) else {
                eprintln!(
                    "nkg: cannot encode index (posting ids not ascending); rebuild with `nkg index`"
                );
                std::process::exit(2);
            };
            put_varint(&mut run, d);
            prev = *id;
        }
        put_u32(&mut hdr, idx.postings.key_at(i));
        put_u32(&mut hdr, run.len() as u32);
        put_u32(&mut hdr, ids.last().copied().unwrap_or(0));
        put_u32(&mut hdr, (blob_base + blobs.len()) as u32);
        blobs.extend_from_slice(&run);
    }
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&blobs);
    out
}

pub(crate) fn parse_index_bin(idx_path: &str, data: std::sync::Arc<memmap2::Mmap>) -> Index {
    let refuse = |why: &str| -> ! {
        refuse_index(idx_path, "truncated binary", &why);
    };
    let mut cur = BIN_MAGIC.len();
    let take = |cur: &mut usize, n: usize| -> &[u8] {
        let end = cur.checked_add(n).unwrap_or(usize::MAX);
        if end > data.len() {
            refuse("unexpected end of file");
        }
        let s = &data[*cur..end];
        *cur = end;
        s
    };
    let u64_at = |cur: &mut usize| -> u64 {
        let b = take(cur, 8);
        u64::from_le_bytes(b.try_into().unwrap())
    };
    let u32_at = |cur: &mut usize| -> u32 {
        let b = take(cur, 4);
        u32::from_le_bytes(b.try_into().unwrap())
    };
    let str_at = |cur: &mut usize| -> String {
        let n = u32_at(cur) as usize;
        if n > data.len() {
            refuse("bad length prefix");
        }
        match std::str::from_utf8(take(cur, n)) {
            Ok(s) => s.to_owned(),
            Err(_) => refuse("non-utf8 path"),
        }
    };
    let root_dev = u64_at(&mut cur);
    let root_ino = u64_at(&mut cur);
    let root = str_at(&mut cur);
    let nfiles = u32_at(&mut cur) as usize;
    if nfiles > data.len() {
        refuse("bad file count");
    }
    let mut files = Vec::with_capacity(nfiles.min(1 << 20));
    for _ in 0..nfiles {
        files.push(str_at(&mut cur));
    }
    let npost = u32_at(&mut cur) as usize;
    if npost > data.len() {
        refuse("bad posting count");
    }
    let hdr = cur;
    let table_end = hdr.saturating_add(npost.saturating_mul(POSTING_HDR));
    if table_end > data.len() {
        refuse("truncated posting header table");
    }
    let mut prev = 0u32;
    let mut first = true;
    #[allow(clippy::chunks_exact_to_as_chunks)]
    for ent in data[hdr..table_end].chunks_exact(POSTING_HDR) {
        let k = u32::from_le_bytes(ent[0..4].try_into().unwrap());
        let blen = u32::from_le_bytes(ent[4..8].try_into().unwrap()) as usize;
        let last = u32::from_le_bytes(ent[8..12].try_into().unwrap());
        let blob_off = u32::from_le_bytes(ent[12..16].try_into().unwrap()) as usize;
        if !first && k <= prev {
            refuse("posting keys out of order");
        }
        first = false;
        prev = k;
        if (last as usize) >= nfiles {
            refuse("posting id out of range");
        }
        if blob_off.saturating_add(blen) > data.len() {
            refuse("bad posting length");
        }
    }
    let postings = Postings::Raw {
        hdr,
        npost,
        data,
        nfiles,
    };
    let idx = Index {
        root,
        root_dev,
        root_ino,
        files,
        postings,
    };
    validate_stored_files(idx_path, &idx.files);
    idx
}

pub(crate) const MAX_INDEX_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub(crate) fn read_index_bytes(idx_path: &str) -> std::sync::Arc<memmap2::Mmap> {
    use memmap2::MmapOptions;
    let f = match std::fs::File::open(idx_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("nkg: cannot read index {idx_path}: {e}");
            std::process::exit(2);
        }
    };
    let len = match f.metadata() {
        Ok(m) => m.len(),
        Err(e) => {
            eprintln!("nkg: cannot read index {idx_path}: {e}");
            std::process::exit(2);
        }
    };
    if len > MAX_INDEX_BYTES {
        eprintln!("nkg: index {idx_path} exceeds 4 GiB: rebuild with `nkg index`");
        std::process::exit(2);
    }
    if len == 0 {
        eprintln!("nkg: unreadable index {idx_path} (empty): rebuild with `nkg index`");
        std::process::exit(2);
    }
    match unsafe { MmapOptions::new().len(len as usize).map(&f) } {
        Ok(m) => std::sync::Arc::new(m),
        Err(e) => {
            eprintln!("nkg: cannot map index {idx_path}: {e}");
            std::process::exit(2);
        }
    }
}
pub(crate) fn parse_index_auto(idx_path: &str, data: std::sync::Arc<memmap2::Mmap>) -> Index {
    if data.starts_with(BIN_MAGIC) {
        return parse_index_bin(idx_path, data);
    }
    if data.starts_with(b"NKGREP") {
        refuse_stale_index(idx_path);
    }
    match std::str::from_utf8(data.as_ref()) {
        Ok(s) => parse_index(idx_path, s),
        Err(e) => refuse_index(idx_path, "old format", &e),
    }
}
pub(crate) fn index_header(idx_path: &str, data: &[u8]) -> (String, u64, u64) {
    if data.starts_with(BIN_MAGIC) {
        return parse_index_header_bin(idx_path, data);
    }
    if data.starts_with(b"NKGREP") {
        refuse_stale_index(idx_path);
    }
    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(e) => refuse_index(idx_path, "old format", &e),
    };
    use serde::de::{IgnoredAny, MapAccess, Visitor};
    struct HeaderVisitor;
    impl<'de> Visitor<'de> for HeaderVisitor {
        type Value = (String, u64, u64);
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("an index header object")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Self::Value, A::Error> {
            let (mut root, mut dev, mut ino) = (None, None, None);
            while let Some(k) = m.next_key::<&str>()? {
                match k {
                    "root" => root = Some(m.next_value()?),
                    "root_dev" => dev = Some(m.next_value()?),
                    "root_ino" => ino = Some(m.next_value()?),
                    _ => {
                        m.next_value::<IgnoredAny>()?;
                    }
                }
            }
            match (root, dev, ino) {
                (Some(r), Some(d), Some(i)) => Ok((r, d, i)),
                _ => Err(serde::de::Error::custom("index header field missing")),
            }
        }
    }
    let mut de = serde_json::Deserializer::from_str(s);
    match serde::Deserializer::deserialize_map(&mut de, HeaderVisitor) {
        Ok(v) => v,
        Err(e) => refuse_index(idx_path, "old format", &e),
    }
}

pub(crate) fn parse_index_header_bin(idx_path: &str, data: &[u8]) -> (String, u64, u64) {
    let mut cur = BIN_MAGIC.len();
    let mut take = |n: usize| -> &[u8] {
        let end = cur.saturating_add(n);
        if end > data.len() {
            refuse_index(idx_path, "truncated binary", &"header past end of file");
        }
        let s = &data[cur..end];
        cur = end;
        s
    };
    let dev = u64::from_le_bytes(take(8).try_into().unwrap());
    let ino = u64::from_le_bytes(take(8).try_into().unwrap());
    let n = u32::from_le_bytes(take(4).try_into().unwrap()) as usize;
    match std::str::from_utf8(take(n)) {
        Ok(r) => (r.to_owned(), dev, ino),
        Err(_) => refuse_index(idx_path, "truncated binary", &"non-utf8 root"),
    }
}

pub(crate) fn read_index_header_bytes(idx_path: &str) -> Vec<u8> {
    use std::io::Read;
    let mut f = match std::fs::File::open(idx_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("nkg: cannot read index {idx_path}: {e}");
            std::process::exit(2);
        }
    };
    const FIXED: usize = 28;
    let mut d = vec![0u8; FIXED];
    if let Err(e) = f.read_exact(&mut d) {
        eprintln!("nkg: unreadable index {idx_path}: {e}");
        std::process::exit(2);
    }
    let root_len = u32::from_le_bytes(d[24..28].try_into().unwrap()) as usize;
    let file_len = f.metadata().map(|m| m.len() as usize).unwrap_or(0);
    if root_len > file_len.saturating_sub(FIXED) {
        eprintln!("nkg: unreadable index {idx_path}: bad root length");
        std::process::exit(2);
    }
    let start = d.len();
    d.resize(start + root_len, 0);
    if let Err(e) = f.read_exact(&mut d[start..]) {
        eprintln!("nkg: unreadable index {idx_path}: {e}");
        std::process::exit(2);
    }
    d
}
