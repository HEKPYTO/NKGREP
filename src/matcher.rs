use crate::verify::FileHits;
use grep_regex::{RegexMatcher, RegexMatcherBuilder};
use std::collections::HashSet;

#[cfg(test)]
use crate::rank::{banked_text, flat_scores, raw_order, verify_batched};
#[cfg(test)]
use crate::verify::*;
#[cfg(test)]
use crate::*;

#[derive(Default)]
pub(crate) struct GramHasher(u64);

impl std::hash::Hasher for GramHasher {
    fn write(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0 = (self.0 ^ *b as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        }
    }

    fn write_u32(&mut self, n: u32) {
        self.0 = (n as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }

    fn finish(&self) -> u64 {
        let mut h = self.0;
        h ^= h >> 32;
        h = h.wrapping_mul(0xD6E8_FEB8_6659_FD93);
        h ^= h >> 32;
        h
    }
}

pub(crate) type GramSet = HashSet<u32, std::hash::BuildHasherDefault<GramHasher>>;

pub(crate) fn grams_of(bytes: &[u8]) -> GramSet {
    let mut set: GramSet = Default::default();
    let n = bytes.len();
    if n < 3 {
        return set;
    }
    if n == 3 {
        set.insert(((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32);
        return set;
    }
    for w in bytes.windows(4) {
        let (a, b, c, d) = (w[0], w[1], w[2], w[3]);
        set.insert(((a as u32) << 16) | ((b as u32) << 8) | c as u32);
        if a == 0 {
            continue;
        }
        set.insert(((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | d as u32);
    }
    set.insert(((bytes[n - 3] as u32) << 16) | ((bytes[n - 2] as u32) << 8) | bytes[n - 1] as u32);
    set
}

#[cfg(test)]
mod gram_hash_tests {
    use super::GramHasher;
    use std::hash::Hasher;

    #[test]
    fn gram_hash_spreads_the_top_control_bits() {
        let mut seen = std::collections::HashSet::new();
        for key in (0u32..4096).map(|k| 0x0100_0000u32 | k) {
            let mut h = GramHasher::default();
            h.write_u32(key);
            seen.insert((h.finish() >> 57) as u8);
        }
        assert!(
            seen.len() >= 100,
            "only {} of 128 control tags used",
            seen.len()
        );
    }
}
fn gram_pack(g: &[u8; 3]) -> u32 {
    ((g[0] as u32) << 16) | ((g[1] as u32) << 8) | (g[2] as u32)
}

pub(crate) fn query_grams(pattern: &str) -> Option<Vec<Vec<u32>>> {
    let mut ors = vec![];
    for branch in split_branches(pattern) {
        if branch_needs_fallback(&branch) {
            return None;
        }
        let mut ands = HashSet::new();
        for run in literal_runs(&branch) {
            if run.len() >= 4 {
                for w in run.windows(4) {
                    if w[0] == 0 {
                        continue;
                    }
                    ands.insert(
                        ((w[0] as u32) << 24)
                            | ((w[1] as u32) << 16)
                            | ((w[2] as u32) << 8)
                            | (w[3] as u32),
                    );
                }
            } else if run.len() == 3 {
                ands.insert(gram_pack(&[run[0], run[1], run[2]]));
            }
        }
        if ands.is_empty() {
            return None;
        }
        let mut grams = ands.into_iter().collect::<Vec<_>>();
        grams.sort();
        ors.push(grams);
    }
    Some(ors)
}

fn branch_needs_fallback(branch: &str) -> bool {
    let mut it = branch.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\\' => {
                let _ = it.next();
            }
            '[' => {
                if it.peek() == Some(&'^') {
                    it.next();
                }
                if it.peek() == Some(&']') {
                    it.next();
                }
                let mut esc = false;
                for c2 in it.by_ref() {
                    if esc {
                        esc = false;
                        continue;
                    }
                    if c2 == '\\' {
                        esc = true;
                        continue;
                    }
                    if c2 == ']' {
                        break;
                    }
                }
            }
            '(' => {
                if it.peek() == Some(&'?') {
                    return true;
                }
            }
            '*' | '?' => return true,
            '{' if it.peek().is_some_and(|p| p.is_ascii_digit()) => return true,
            '{' => {}
            _ => {}
        }
    }
    false
}

fn split_branches(pattern: &str) -> Vec<String> {
    let mut out: Vec<String> = vec![String::new()];
    let mut it = pattern.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\\' => {
                out.last_mut().unwrap().push('\\');
                if let Some(e) = it.next() {
                    out.last_mut().unwrap().push(e);
                }
            }
            '[' => {
                let mut cls = String::from("[");
                if it.peek() == Some(&'^') {
                    cls.push(it.next().unwrap());
                }
                if it.peek() == Some(&']') {
                    cls.push(it.next().unwrap()); // `[]...]` — first ] literal
                }
                {
                    let iter = it.by_ref();
                    while let Some(c2) = iter.next() {
                        cls.push(c2);
                        if c2 == '\\' {
                            if let Some(e) = iter.next() {
                                cls.push(e); // escaped char inside class
                            }
                            continue;
                        }
                        if c2 == ']' {
                            break;
                        }
                    }
                }
                out.last_mut().unwrap().push_str(&cls);
            }
            '|' => out.push(String::new()),
            c => out.last_mut().unwrap().push(c),
        }
    }
    out
}

fn literal_runs(branch: &str) -> Vec<Vec<u8>> {
    let mut runs = vec![];
    let mut cur: Vec<u8> = vec![];
    let mut it = branch.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\\' => {
                if !cur.is_empty() {
                    runs.push(std::mem::take(&mut cur));
                }
                let _ = it.next(); // escaped char is never a literal
            }
            '[' => {
                if !cur.is_empty() {
                    runs.push(std::mem::take(&mut cur));
                }
                if it.peek() == Some(&'^') {
                    it.next();
                }
                if it.peek() == Some(&']') {
                    it.next();
                }
                let mut esc = false;
                for c2 in it.by_ref() {
                    if esc {
                        esc = false;
                        continue;
                    }
                    if c2 == '\\' {
                        esc = true;
                        continue;
                    }
                    if c2 == ']' {
                        break;
                    }
                }
            }
            c if c.is_ascii_alphanumeric() || c == '_' => cur.push(c as u8),
            '.' | '^' | '$' | '*' | '+' | '?' | '(' | ')' | ']' | '{' | '}' | '|' => {
                if !cur.is_empty() {
                    runs.push(std::mem::take(&mut cur));
                }
            }
            c if (c as u32) < 128 => cur.push(c as u8),
            _ => {
                if !cur.is_empty() {
                    runs.push(std::mem::take(&mut cur));
                }
            }
        }
    }
    if !cur.is_empty() {
        runs.push(cur);
    }
    runs
}

pub(crate) fn build_matcher(
    pattern: &str,
    case_insensitive: bool,
) -> Result<RegexMatcher, grep_regex::Error> {
    let ascii_only = pattern.is_ascii() && !case_insensitive;
    let literal_only = is_pure_literal(pattern);
    if case_insensitive || ascii_only || literal_only {
        let mut b = RegexMatcherBuilder::new();
        if case_insensitive {
            b.case_insensitive(true);
        }
        if ascii_only {
            b.unicode(false);
            b.line_terminator(Some(b'\n'));
        }
        if literal_only {
            b.fixed_strings(true);
        }
        if let Ok(m) = b.build(pattern) {
            return Ok(m);
        }
        if ascii_only {
            let mut bz = RegexMatcherBuilder::new();
            bz.unicode(false);
            if literal_only {
                bz.fixed_strings(true);
            }
            if let Ok(m) = bz.build(pattern) {
                return Ok(m);
            }
        }
        if case_insensitive {
            let mut bi = RegexMatcherBuilder::new();
            bi.case_insensitive(true);
            if let Ok(m) = bi.build(pattern) {
                return Ok(m);
            }
        }
    }
    RegexMatcher::new(pattern)
}
fn is_pure_literal(pattern: &str) -> bool {
    if pattern.is_empty() || !pattern.is_ascii() {
        return false;
    }
    let branches = split_branches(pattern);
    if branches.len() != 1 {
        return false;
    }
    let runs = literal_runs(&branches[0]);
    runs.len() == 1 && runs[0].len() == pattern.len()
}
fn regex_escape_into(out: &mut String, s: &str) {
    for c in s.chars() {
        if matches!(
            c,
            '\\' | '.'
                | '+'
                | '*'
                | '?'
                | '('
                | ')'
                | '|'
                | '['
                | ']'
                | '{'
                | '}'
                | '^'
                | '$'
                | '#'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
}

pub(crate) fn combine_patterns(patterns: &[String], fixed: bool) -> String {
    if patterns.len() == 1 {
        return patterns[0].clone();
    }
    let mut out = String::new();
    for (k, p) in patterns.iter().enumerate() {
        if k > 0 {
            out.push('|');
        }
        out.push_str("(?:");
        if fixed {
            regex_escape_into(&mut out, p);
        } else {
            out.push_str(p);
        }
        out.push(')');
    }
    out
}

pub(crate) fn build_matcher_opts(
    pattern: &str,
    case_insensitive: bool,
    word: bool,
    fixed: bool,
) -> Result<RegexMatcher, grep_regex::Error> {
    if !word && !fixed {
        return build_matcher(pattern, case_insensitive);
    }
    let ascii_only = pattern.is_ascii() && !case_insensitive && !word;
    let mut b = RegexMatcherBuilder::new();
    if case_insensitive {
        b.case_insensitive(true);
    }
    if word {
        b.word(true);
    }
    if ascii_only {
        b.unicode(false);
        b.line_terminator(Some(b'\n'));
    }
    if fixed {
        b.fixed_strings(true);
    }
    if let Ok(m) = b.build(pattern) {
        return Ok(m);
    }
    if ascii_only {
        let mut bz = RegexMatcherBuilder::new();
        bz.unicode(false);
        if word {
            bz.word(true);
        }
        if fixed {
            bz.fixed_strings(true);
        }
        if let Ok(m) = bz.build(pattern) {
            return Ok(m);
        }
    }
    if case_insensitive {
        let mut bi = RegexMatcherBuilder::new();
        bi.case_insensitive(true);
        if word {
            bi.word(true);
        }
        if fixed {
            bi.fixed_strings(true);
        }
        if let Ok(m) = bi.build(pattern) {
            return Ok(m);
        }
    }
    let mut bf = RegexMatcherBuilder::new();
    if word {
        bf.word(true);
    }
    if fixed {
        bf.fixed_strings(true);
    }
    bf.build(pattern)
}

pub(crate) fn query_grams_multi(patterns: &[String], fixed: bool) -> Option<Vec<Vec<u32>>> {
    if !fixed && patterns.len() == 1 {
        return query_grams(&patterns[0]);
    }
    let mut ors: Vec<Vec<u32>> = vec![];
    for p in patterns {
        if fixed {
            let bytes = p.as_bytes();
            if bytes.len() < 3 {
                return None;
            }
            let mut set = HashSet::new();
            for w in bytes.windows(3) {
                set.insert(gram_pack(&[w[0], w[1], w[2]]));
            }
            ors.push(set.into_iter().collect());
        } else {
            let mut branches = query_grams(p)?;
            ors.append(&mut branches);
        }
    }
    Some(ors)
}

pub(crate) fn apply_max_count(hits: &mut [FileHits], max_count: Option<usize>) {
    if let Some(m) = max_count {
        for fh in hits.iter_mut() {
            fh.metas.truncate(m);
        }
    }
}

pub(crate) fn split_pattern_lines(data: &[u8]) -> Vec<String> {
    if data.is_empty() {
        return vec![];
    }
    let text = String::from_utf8_lossy(data);
    let mut out: Vec<String> = text
        .split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l).to_string())
        .collect();
    if text.ends_with('\n') {
        out.pop();
    }
    out
}

#[cfg(test)]
mod literal_tests {
    use super::*;

    fn sorted_branches(pat: &str) -> Option<Vec<Vec<u32>>> {
        query_grams(pat).map(|mut ors| {
            for b in &mut ors {
                b.sort();
            }
            ors.sort();
            ors
        })
    }

    #[test]
    fn escaped_pipe_stays_one_branch() {
        let got = sorted_branches("abc\\|def").unwrap();
        assert_eq!(got.len(), 1, "escaped pipe must not split: {got:?}");
        assert!(got[0].contains(&gram_pack(b"abc")), "{got:?}");
        assert!(got[0].contains(&gram_pack(b"def")), "{got:?}");
    }

    #[test]
    fn escaped_pipe_branch_still_indexes() {
        let got = sorted_branches("needle_1\\|x|NEEDLE_ALPHA").unwrap();
        assert_eq!(got.len(), 2, "{got:?}");
    }

    #[test]
    fn class_pipe_does_not_split() {
        let got = sorted_branches("[a|b]+needle_1").unwrap();
        assert_eq!(got.len(), 1, "class pipe must not split: {got:?}");
        assert!(
            got[0].contains(
                &(((b'n' as u32) << 24)
                    | ((b'e' as u32) << 16)
                    | ((b'e' as u32) << 8)
                    | (b'd' as u32))
            ),
            "{got:?}"
        );
    }

    #[test]
    fn group_alternation_splits() {
        let got = sorted_branches("(needle_1|needle_2)_suffix").unwrap();
        assert_eq!(got.len(), 2, "{got:?}");
    }
    #[test]
    fn cached_verify_matches_plain() {
        let dir = std::env::temp_dir().join(format!("nkg_cached_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.txt");
        std::fs::write(&a, "needle here\nsecond needle\n").unwrap();
        let ap = a.to_string_lossy().into_owned();
        let matcher = RegexMatcher::new("needle").unwrap();
        let fdc = FdCache::new(1);
        let latch = AtomicBool::new(false);
        let plain =
            verify_one_raw(&latch, 0, &ap, &matcher, 10.0, false, None).expect("plain must hit");
        let cached = verify_one_raw_cached(&latch, 0, &ap, &matcher, 10.0, Some((&fdc, 0)), false)
            .expect("cached must hit");
        assert_eq!(cached.metas.len(), plain.metas.len());
        for (c, p) in cached.metas.iter().zip(plain.metas.iter()) {
            assert_eq!((c.line, c.score), (p.line, p.score));
            assert_eq!(banked_text(&cached, c), banked_text(&plain, p));
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn no_literal_falls_back() {
        assert!(query_grams("a|b").is_none());
        assert!(query_grams(".*").is_none());
        assert!(query_grams("a\\|b").is_none()); // single branch, runs < 3
    }
    #[test]
    fn group_and_repeat_falls_back() {
        assert!(query_grams("(?i)needle_alpha").is_none());
        assert!(query_grams("(?P<word>NEEDLE_ALPHA)").is_none());
        assert!(query_grams("(?#comment)NEEDLE_ALPHA").is_none());
        assert!(query_grams("NEEDLE_[A-Z]{2,}").is_none());
        assert!(query_grams("confi{1,}g").is_none());
        assert!(query_grams("[(?]needle_alpha").is_some());
    }

    #[test]
    fn plain_queries_unchanged() {
        assert!(query_grams("TODO_FIXME_ALPHA").is_some());
        assert_eq!(
            sorted_branches("needle_1|needle_2|needle_3").unwrap().len(),
            3
        );
        assert_eq!(sorted_branches("fn parse_config").unwrap().len(), 1);
    }
    #[test]
    fn pack_bijective_and_ordered() {
        let mut seen = std::collections::HashSet::new();
        for a in [0u8, 1, 65, 95, 122, 200, 255] {
            for b in [0u8, 1, 65, 95, 122, 200, 255] {
                for c in [0u8, 1, 65, 95, 122, 200, 255] {
                    let k = gram_pack(&[a, b, c]);
                    assert_eq!(k >> 24, 0, "top byte must stay zero");
                    assert_eq!(((k >> 16) & 0xFF) as u8, a);
                    assert_eq!(((k >> 8) & 0xFF) as u8, b);
                    assert_eq!((k & 0xFF) as u8, c);
                    assert!(seen.insert(k), "collision on [{a}, {b}, {c}]");
                }
            }
        }
        let mut trips: Vec<[u8; 3]> = vec![
            *b"abc", *b"abd", *b"bac", *b"aaa", *b"zzz", *b"a_c", *b"_aa",
        ];
        trips.sort();
        let mut packed: Vec<u32> = trips.iter().map(gram_pack).collect();
        packed.sort();
        assert_eq!(packed, trips.iter().map(gram_pack).collect::<Vec<_>>());
    }
    #[test]
    fn top_zero_indexed_matches_scan_empty() {
        let dir = std::env::temp_dir().join(format!("nkg_top0_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.txt");
        let b = dir.join("b.txt");
        std::fs::write(&a, "needle_haystack_content\n").unwrap();
        std::fs::write(&b, "needle_haystack_content\n").unwrap();
        let idx = Index {
            root: String::new(),
            root_dev: 0,
            root_ino: 0,
            files: vec![
                a.to_string_lossy().into_owned(),
                b.to_string_lossy().into_owned(),
            ],
            postings: Postings::default(),
        };
        let matcher = RegexMatcher::new("needle_haystack_content").unwrap();
        let order = vec![0u32, 1u32];
        let scores = vec![10.0f64, 5.0f64];
        let latch = AtomicBool::new(false);
        let batched = verify_batched(&order, &scores, Some(0), false, |id| {
            verify_one_raw_ctx(VerifyInput {
                err: &latch,
                pid: id,
                path: &idx.files[id as usize],
                matcher: &matcher,
                file_score: scores[id as usize],
                before: 0,
                after: 0,
                invert: false,
                follow: false,
                match_limit: None,
            })
        });
        let scanned_all: Vec<FileHits> = [(0u32, 10.0f64), (1u32, 5.0f64)]
            .into_iter()
            .filter_map(|(id, s)| {
                verify_one_raw_cached(
                    &latch,
                    id,
                    &idx.files[id as usize],
                    &matcher,
                    s,
                    None,
                    false,
                )
            })
            .collect();
        let (scanned_scores, _) = flat_scores(&scanned_all);
        let mut scanned_ord = raw_order(&scanned_scores);
        scanned_ord.clear();
        assert!(batched.is_empty(), "top=0 batched must return 0 hits");
        assert!(scanned_ord.is_empty(), "top=0 scan must return 0 hits");
        assert!(!scanned_all.is_empty(), "fixture must match without top");
        std::fs::remove_dir_all(&dir).ok();
    }
    #[test]
    fn matchflags_combine_scopes_groups() {
        let one = |s: &str| s.to_string();
        assert_eq!(combine_patterns(&[one("a|b")], false), "a|b");
        assert_eq!(
            combine_patterns(&[one("(?i)foo"), one("BAR")], false),
            "(?:(?i)foo)|(?:BAR)"
        );
        assert_eq!(
            combine_patterns(&[one("(a|b)"), one("c")], false),
            "(?:(a|b))|(?:c)"
        );
        assert_eq!(
            combine_patterns(&[one("a.c"), one("x|y")], true),
            "(?:a\\.c)|(?:x\\|y)"
        );
        assert_eq!(combine_patterns(&[one("a.c")], true), "a.c");
    }

    #[test]
    fn matchflags_grams_multi() {
        let one = |s: &str| s.to_string();
        assert_eq!(
            query_grams_multi(&[one("NEEDLE_ALPHA")], false),
            query_grams("NEEDLE_ALPHA")
        );
        let g = query_grams_multi(&[one("foo*bar")], true).unwrap();
        assert_eq!(g.len(), 1);
        assert!(g[0].contains(&gram_pack(b"foo")));
        assert!(g[0].contains(&gram_pack(b"bar")));
        let u = query_grams_multi(&[one("NEEDLE_ALPHA"), one("needle_1")], false).unwrap();
        assert_eq!(u.len(), 2);
        assert!(query_grams_multi(&[one("NEEDLE_ALPHA"), one("a|b")], false).is_none());
        assert!(query_grams_multi(&[one("")], true).is_none());
        assert!(query_grams_multi(&[one("ab")], true).is_none());
    }

    #[test]
    fn matchflags_pattern_lines() {
        let v = |b: &[u8]| split_pattern_lines(b);
        assert!(v(b"").is_empty());
        assert_eq!(v(b"a\n"), vec!["a"]);
        assert_eq!(v(b"a\n\nb\n"), vec!["a", "", "b"]);
        assert_eq!(v(b"\n"), vec![""]);
        assert_eq!(v(b"a\r\nb\r\n"), vec!["a", "b"]);
        assert_eq!(v(b"a\rb"), vec!["a\rb"]);
    }

    #[test]
    fn matchflags_matcher_word_fixed() {
        let w = build_matcher_opts("foo", false, true, false).unwrap();
        for (line, want) in [
            ("a foo b", 1),
            ("foobar", 0),
            ("foo_bar", 0),
            ("foo-bar", 1),
            ("foo", 1),
        ] {
            let mut s = grep_searcher::SearcherBuilder::new().build();
            let mut sink = ColCollector {
                arena: vec![],
                metas: vec![],
                path_bonus: 0.0,
                match_limit: None,
            };
            s.search_slice(&w, line.as_bytes(), &mut sink).unwrap();
            assert_eq!(sink.metas.len(), want, "word line {line:?}");
        }
        let f = build_matcher_opts("a.c", false, false, true).unwrap();
        let mut s = grep_searcher::SearcherBuilder::new().build();
        let mut sink = ColCollector {
            arena: vec![],
            metas: vec![],
            path_bonus: 0.0,
            match_limit: None,
        };
        s.search_slice(&f, b"a.c axc", &mut sink).unwrap();
        assert_eq!(sink.metas.len(), 1);
        assert_eq!(sink.arena, b"a.c axc");
    }

    #[test]
    fn matchflags_invert_and_max_count() {
        let dir = std::env::temp_dir().join(format!("nkg_matchflags_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.txt");
        std::fs::write(&a, "foo one\nbar two\nfoo three\nbaz four\n").unwrap();
        let ap = a.to_string_lossy().into_owned();
        let m = RegexMatcher::new("foo").unwrap();
        let latch = AtomicBool::new(false);
        let norm = verify_one_raw_ctx(VerifyInput {
            err: &latch,
            pid: 0,
            path: &ap,
            matcher: &m,
            file_score: 0.0,
            before: 0,
            after: 0,
            invert: false,
            follow: false,
            match_limit: None,
        })
        .expect("plain must hit");
        assert_eq!(norm.metas.len(), 2);
        let inv = verify_one_raw_ctx(VerifyInput {
            err: &latch,
            pid: 0,
            path: &ap,
            matcher: &m,
            file_score: 0.0,
            before: 0,
            after: 0,
            invert: true,
            follow: false,
            match_limit: None,
        })
        .expect("invert must hit");
        assert_eq!(inv.metas.len(), 2);
        assert_eq!((inv.metas[0].line, inv.metas[1].line), (2, 4));
        assert_eq!(banked_text(&inv, &inv.metas[0]), "bar two");
        let inv_c = verify_one_raw_cached_ctx(CachedVerify {
            err: &latch,
            pid: 0,
            path: &ap,
            matcher: &m,
            file_score: 0.0,
            before: 0,
            after: 0,
            fdc: None,
            invert: true,
            follow: false,
        })
        .expect("cached invert");
        assert_eq!(inv_c.metas.len(), 2);
        assert_eq!(inv_c.metas[0].line, 2);
        let mut capped = verify_one_raw_ctx(VerifyInput {
            err: &latch,
            pid: 0,
            path: &ap,
            matcher: &m,
            file_score: 0.0,
            before: 0,
            after: 0,
            invert: false,
            follow: false,
            match_limit: None,
        })
        .unwrap();
        apply_max_count(std::slice::from_mut(&mut capped), Some(1));
        assert_eq!(capped.metas.len(), 1);
        assert_eq!(capped.metas[0].line, 1);
        std::fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
mod escape_tests {
    use super::*;

    fn quoted_manual(s: &str) -> Vec<u8> {
        let mut m = Vec::with_capacity(s.len() + 2);
        m.push(b'"');
        push_escaped_json(&mut m, s);
        m.push(b'"');
        m
    }

    fn check_str(s: &str) {
        let o = serde_json::to_vec(&s).unwrap();
        assert_eq!(quoted_manual(s), o, "escape divergence on {s:?}");
    }

    fn check_hit(path: &str, line: u64, text: &str, score: f64) {
        let h = Hit {
            path: Arc::new(path.to_string()),
            line,
            text: text.to_string(),
            score,
        };
        let mut m = Vec::new();
        let mut p = Vec::with_capacity(h.path.len() + 2);
        push_escaped_json(&mut p, &h.path);
        emit_raw_with_path(&mut m, &p, h.line, &h.text, h.score);
        let mut o = serde_json::to_vec(&h).unwrap();
        o.push(b'\n');
        assert_eq!(m, o, "hit divergence on {path:?}:{line}:{text:?}:{score:?}");
    }

    #[test]
    fn fuzz_vs_serde_full_matrix() {
        for b in 0u8..=0x7Fu8 {
            check_str(&char::from_u32(b as u32).unwrap().to_string());
        }
        let mut specials: Vec<char> = (0u8..0x20).map(|b| b as char).collect();
        specials.push('"');
        specials.push('\\');
        for c in &specials {
            check_str(&format!("a{c}b"));
            check_str(&format!("{c}lead"));
            check_str(&format!("trail{c}"));
        }
        for a in &specials {
            for b in &specials {
                check_str(&format!("{a}{b}"));
                check_str(&format!("x{a}y{b}z"));
            }
        }
        for s in [
            "\x7f",
            "caf\u{e9}",
            "\u{1f600}",
            "\u{fffd}",
            "\u{4e2d}\u{6587}",
            "e\u{301}",
            "a/b\\c",
            "/abs/path/x.txt",
            "tab\there",
            "nl\nhere",
            "cr\rhere",
            "bs\x08here",
            "ff\x0chere",
            "q\"q",
            "b\\b",
            "\"quoted\"",
            "\\\\unc\\\\path",
            "",
            "plain ascii line with spaces 123",
        ] {
            check_str(s);
        }
        let texts = [
            "plain",
            "q\"q\\",
            "a\nb\tc",
            "\x01\x02\x1f mid \x7f",
            "uni \u{1f600} \u{fffd}",
            "",
            "trail\\",
        ];
        let lines = [0u64, 1, 42, u64::MAX];
        let scores = [
            0.0,
            -0.0,
            1.5,
            -42.25,
            123456.789,
            1e-7,
            1e300,
            99.999999,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::NAN,
        ];
        for t in texts {
            for l in lines {
                for s in scores {
                    check_hit("corpus/pkg_0/m_0.txt", l, t, s);
                    check_hit("we\"ird\\path\x01.txt", l, t, s);
                }
            }
        }
    }

    #[test]
    fn fuzz_vs_serde_corpus_bytes() {
        let root = std::path::Path::new("bench/corpus");
        if !root.exists() {
            return;
        }
        let mut files: Vec<std::path::PathBuf> = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    files.push(p);
                }
            }
        }
        files.sort();
        let mut n = 0usize;
        for p in &files {
            check_str(&p.to_string_lossy());
            let data = std::fs::read(p).unwrap();
            for line in data.split(|&b| b == b'\n') {
                let s = String::from_utf8_lossy(line);
                check_str(&s);
                if n < 2000 && line.as_ptr() == data.as_ptr() {
                    check_hit(&p.to_string_lossy(), 1, &s, 12.5);
                }
                n += 1;
                if n >= 60000 {
                    return;
                }
            }
        }
        assert!(n > 1000, "corpus fuzz saw too few lines: {n}");
    }
}
