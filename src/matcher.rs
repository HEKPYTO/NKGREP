use crate::FileHits;
use grep_regex::{RegexMatcher, RegexMatcherBuilder};
use std::collections::HashSet;

#[cfg(test)]
use crate::*;

/// Multiply-xorshift finalizer for the build's gram set. A gram key is a
/// packed byte window that is already close to its own hash, so SipHash-1-3's
/// key mixing buys nothing here and lands on the index build's hottest loop
/// (every window of every file hashes once). The xorshift-multiply rounds are
/// what makes the TOP 7 bits vary: hashbrown derives its bucket from the low
/// bits and its control byte from the top 7, and a bare multiply leaves the
/// top bits of a 32-bit input zero.
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

/// Distinct grams of BOTH widths in one set, packed into the same `u32` key
/// space. The widths are kept disjoint by construction rather than by a tag
/// bit: a trigram packs into 24 bits with the top byte always zero, a
/// four-gram uses all 32, and a four-gram whose first byte is NUL is skipped
/// (that is a binary file, which is never indexed anyway). So every 3-gram key
/// is < 2^24 and every 4-gram key is >= 2^24, and one sorted key table holds
/// both without collisions.
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
    // One pass for both widths. Two `windows` walks read the whole buffer
    // twice and insert about 38 million times over 19 MB of source; deriving
    // the trigram from the same window as the four-gram halves the memory
    // traffic without changing which grams are produced.
    for w in bytes.windows(4) {
        let (a, b, c, d) = (w[0], w[1], w[2], w[3]);
        set.insert(((a as u32) << 16) | ((b as u32) << 8) | c as u32);
        if a == 0 {
            continue;
        }
        set.insert(((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | d as u32);
    }
    // The final three bytes form a trigram no four-byte window can reach.
    set.insert(((bytes[n - 3] as u32) << 16) | ((bytes[n - 2] as u32) << 8) | bytes[n - 1] as u32);
    set
}

#[cfg(test)]
mod gram_hash_tests {
    use super::GramHasher;
    use std::hash::Hasher;

    /// hashbrown picks the bucket from the low bits and the control byte from
    /// the TOP 7, and packed 4-grams leave the top half of a plain multiply
    /// zero. Assert the high bits actually move for a dense run of real gram
    /// keys, so a retuned constant cannot silently re-bury them (that costs
    /// correctness nothing and build time ~10x).
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
/// Bijective trigram pack: (a<<16)|(b<<8)|c. Numeric order equals
/// lexicographic byte order, so sorted keys stay byte-stable across the
/// format rev. Top byte always zero; unpack is (k>>16, k>>8, k) & 0xFF.
fn gram_pack(g: &[u8; 3]) -> u32 {
    ((g[0] as u32) << 16) | ((g[1] as u32) << 8) | (g[2] as u32)
}

/// Regex-aware literal extraction: split into alternation branches on `|`
/// that is neither escaped nor inside a `[...]` class; per branch, runs of
/// [A-Za-z0-9_] len>=3 give required trigrams. Group depth is ignored on
/// purpose: `(a|b)` still alternates, so its `|` separates branches, and
/// each branch's grams remain a subset of its match text, keeping the union
/// a superset of all matches. Escapes (`\x`) never contribute a literal
/// (covers `\|`, `\d`, `\n`, `\\`); class contents contribute nothing.
/// None = no usable literal in some branch, caller must full-scan.
pub(crate) fn query_grams(pattern: &str) -> Option<Vec<Vec<u32>>> {
    let mut ors = vec![];
    for branch in split_branches(pattern) {
        // Soundness fallback: `(?` changes literal semantics (flags `(?i)`,
        // groups `(?P<>)`, comments `(?#)`, lookaround) and `{n}`/`*`/`?`
        // can drop a required trigram (`ABCDEF{0}` matches `ABCDE`, which
        // lacks `DEF`; `NEEDLE_ALPHA?` matches `NEEDLE_ALPH`, lacking `PHA`).
        // Any of them forces a full scan; `+` keeps every literal run.
        if branch_needs_fallback(&branch) {
            return None;
        }
        let mut ands = HashSet::new();
        for run in literal_runs(&branch) {
            if run.len() >= 4 {
                // A run of four or more bytes yields four-grams. Intersecting
                // them is far more selective than three-grams alone, because
                // the file must hold the run's bytes adjacently rather than
                // merely contain each gram somewhere -- which is the whole
                // gap against an index that enforces adjacency.
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
                // Too short for a four-gram; the three-gram is still required.
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

/// True when a split branch contains an unescaped `(?` (flags, named groups,
/// comments, lookaround), an unescaped `{`+digit repetition, or an unescaped
/// `*`/`?` quantifier outside a `[...]` class. Each can drop a required
/// trigram (`ABCDEF{0}` matches `ABCDE` which lacks `DEF`; `NEEDLE_ALPHA?`
/// matches `NEEDLE_ALPH` which lacks `PHA`), so any of them forces a full
/// scan. `+` stays indexed: it keeps at least one copy of its atom, so every
/// match still contains the literal run. Escapes and class contents are
/// skipped exactly as `literal_runs` skips them, so an escaped/literal
/// `(?`, `{2}`, `*`, or `?` never forces a fallback it does not need.
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

/// Split on unescaped `|` outside `[...]` classes. Verbatim copy otherwise
/// (escapes and classes preserved for `literal_runs` to interpret).
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

/// Definitely-literal alphanumeric-underscore runs: skips `\x` escapes and
/// `[...]` class contents (an unclosed `[` swallows the rest, conservatively
/// yielding fewer grams, never wrong ones).
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
            // Punctuation is literal in a regex, so it continues the run instead
            // of breaking it: `Result<T, E>` must yield the cross-boundary
            // trigrams `lt<`, `t<T`, `<T,`, `T<,`, `T, `, `, E`, ` E>` as
            // well as `res`..`ult`. Those are far rarer than the alnum-only
            // grams and cut the verified candidate set sharply.
            //
            // EVERY metacharacter must break a run, quantifiers included: a
            // required trigram has to appear in every match, and `AB+C` matches
            // `ABC`, so a run of `AB+C` would demand `AB+` and silently skip
            // the match. `branch_needs_fallback` screens `*`, `?` and `{`,
            // but it deliberately lets `+` through (`+` preserves the literal
            // run, which mattered when only alnum bytes formed runs). The list
            // is therefore complete rather than filtered by what upstream
            // happens to reject. `[` and `\` are consumed by the arms above;
            // a bare `]` cannot start a class, so it breaks here. `|` is split
            // into branches upstream but is listed anyway so the set stays
            // complete if that ever changes.
            '.' | '^' | '$' | '*' | '+' | '?' | '(' | ')' | ']' | '{' | '}' | '|' => {
                if !cur.is_empty() {
                    runs.push(std::mem::take(&mut cur));
                }
            }
            c if (c as u32) < 128 => cur.push(c as u8),
            // Non-ASCII: a byte-level trigram over its UTF-8 form is not a
            // substring the index can be asked for, so keep the old behavior.
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

/// Matcher construction: ASCII-gated fast path (V1) plus the `-i` gate.
/// Default (`case_insensitive=false`) is the exact V1 sequence: ASCII
/// patterns skip the Unicode tables (`unicode(false)` + `\n` line
/// terminator, unlocking the fast line-oriented path) and pure literals add
/// `fixed_strings`; each keeps independently, builder errors retry
/// less-gated down to plain `RegexMatcher::new`, so construction never
/// fails where it used to work.
/// `-i` keeps the Unicode tables on purpose: `case_insensitive(true)` with
/// Unicode is full simple-fold insensitivity (ripgrep-compatible: `hello`
/// finds `HELLO`, `café` finds `CAFÉ`), while adding `unicode(false)`
/// would shrink folding to ASCII only. The cost is the Unicode tables on
/// `-i` queries alone; the default path is untouched. `fixed_strings` still
/// applies to pure literals (the engine folds literals itself). The final
/// fallback keeps `case_insensitive(true)` so `-i` never silently degrades
/// to case-sensitive; a truly bad pattern still returns Err (exit 2).
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
/// Pure-literal probe for the `fixed_strings` gate: one `|`-free branch whose
/// every byte survives `literal_runs` as a single run. Conservative on
/// purpose: any metachar, escape, class, or alternation disqualifies (that
/// query keeps the regex engine, gaining only `unicode(false)` when ASCII).
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
/// MatchFlags (-m/-e/-f/-F/-v/-w): multi-pattern + matcher-flag layer.
/// Shapes probed against rg 15.1.0; deviations noted inline.
///
/// Patterns arrive as a list (positional, `-e` repeats, `-f` lines). The
/// matcher sees one alternation; the prefilter sees per-pattern branches.
fn regex_escape_into(out: &mut String, s: &str) {
    // Escape set for regex-syntax: every other byte (incl. multibyte UTF-8)
    // passes through verbatim.
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

/// Combine CLI patterns into one alternation. Every branch is wrapped in
/// `(?:...)` so inline flags (`(?i)`) stay scoped to their own pattern —
/// rg 15.1.0 does not leak flags across `-e` (probed) — and an inner `|`
/// can never merge branches (a naive join would split `(a|b)|c` into
/// `(a`, `b)`, `c`, requiring `a` of every match: unsound). Fixed mode
/// pre-escapes each pattern so the combined string stays a plain regex
/// alternation (`fixed_strings` would treat the separators literally).
pub(crate) fn combine_patterns(patterns: &[String], fixed: bool) -> String {
    // A lone pattern needs no alternation: return it verbatim. (Wrapping a
    // single fixed pattern in `(?:...)` would make `fixed_strings` search
    // for the wrappers literally.)
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

/// Extended matcher entry: `word` adds word-boundary matching and keeps the
/// Unicode tables on (the ASCII `unicode(false)` gate would shrink
/// boundaries to ASCII, but rg 15.1.0 treats é as a word char — probed:
/// `-w foo` skips `fooé` yet takes `foo-bar`); `fixed` treats the pattern
/// literally (callers pass it only for a single pattern; multi-pattern
/// fixed arrives pre-escaped via `combine_patterns`). With both unset this
/// delegates to `build_matcher` exactly, so the default path is untouched
/// by construction.
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
    // Same less-gated retries as `build_matcher`, each keeping word+fixed
    // so a retry never silently drops them; the final fallback keeps them
    // too, and a truly bad pattern still returns Err (exit 2).
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

/// Multi-pattern prefilter branches. Single non-fixed delegates to
/// `query_grams` exactly (default path identical). Fixed patterns are
/// literals: every 3-byte window is required (a literal matches only text
/// containing it whole), so short (<3 B) or empty patterns yield None
/// (full scan — an empty pattern matches every line). Multi-pattern ORs
/// every pattern's branches; any pattern without usable grams forces None,
/// since it can match files lacking the other patterns' grams.
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

/// Per-file cap (`-m`): keep the first m banked hits per file. Bank order is
/// file order, so this equals early exit with the same survivors; it runs
/// after verify (no sink change) and before rank/top/count/emit, matching
/// rg's capped `-c` shape. `None` (no `-m`) is a no-op.
pub(crate) fn apply_max_count(hits: &mut [FileHits], max_count: Option<usize>) {
    if let Some(m) = max_count {
        for fh in hits.iter_mut() {
            fh.metas.truncate(m);
        }
    }
}

/// Split `-f` bytes into patterns: one per `\n`, a single trailing `\r`
/// stripped per line, interior empty lines kept (rg 15.1.0: an empty `-f`
/// line matches every line — probed), the trailing-newline artifact
/// dropped, and a fully empty file yielding zero patterns (rg: `-f` with
/// no patterns matches nothing — probed).
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
        // `abc\|def` is a single literal `abc|def`, not an alternation.
        let got = sorted_branches("abc\\|def").unwrap();
        assert_eq!(got.len(), 1, "escaped pipe must not split: {got:?}");
        assert!(got[0].contains(&gram_pack(b"abc")), "{got:?}");
        assert!(got[0].contains(&gram_pack(b"def")), "{got:?}");
    }

    #[test]
    fn escaped_pipe_branch_still_indexes() {
        // Naive `split('|')` yields a bare `x` branch -> None (full scan).
        // Proper parse keeps 2 branches, both with usable literals.
        let got = sorted_branches("needle_1\\|x|NEEDLE_ALPHA").unwrap();
        assert_eq!(got.len(), 2, "{got:?}");
    }

    #[test]
    fn class_pipe_does_not_split() {
        let got = sorted_branches("[a|b]+needle_1").unwrap();
        assert_eq!(got.len(), 1, "class pipe must not split: {got:?}");
        // Runs of four or more now yield four-grams, so the proxy for "this
        // branch kept its literal" is a four-gram of `needle_1`.
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
        // The fd-cache read path (`Some`) must bank the same hits as the
        // plain path (`None`): byte-identical decoded text, line, and score.
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
        // `(?` (flags, named groups, comments, lookaround) and `{n}`
        // repetition can drop a required trigram: full scan.
        assert!(query_grams("(?i)needle_alpha").is_none());
        assert!(query_grams("(?P<word>NEEDLE_ALPHA)").is_none());
        assert!(query_grams("(?#comment)NEEDLE_ALPHA").is_none());
        assert!(query_grams("NEEDLE_[A-Z]{2,}").is_none());
        assert!(query_grams("confi{1,}g").is_none());
        // Escaped or class-contained `(?` / `{d` stay literal: indexable.
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
        // Bijective: distinct triples pack distinctly, top byte stays zero.
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
        // Numeric order equals lexicographic byte order.
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
        // Columnar flat scan (serve semantics): full verify, rank over side
        // scores, top-0 truncate.
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
        // Single non-fixed passes through verbatim (default path identical).
        assert_eq!(combine_patterns(&[one("a|b")], false), "a|b");
        // Wrapping keeps (?i) scoped and inner | from merging branches.
        assert_eq!(
            combine_patterns(&[one("(?i)foo"), one("BAR")], false),
            "(?:(?i)foo)|(?:BAR)"
        );
        assert_eq!(
            combine_patterns(&[one("(a|b)"), one("c")], false),
            "(?:(a|b))|(?:c)"
        );
        // Fixed pre-escapes so separators stay regex alternation.
        assert_eq!(
            combine_patterns(&[one("a.c"), one("x|y")], true),
            "(?:a\\.c)|(?:x\\|y)"
        );
        assert_eq!(combine_patterns(&[one("a.c")], true), "a.c");
    }

    #[test]
    fn matchflags_grams_multi() {
        let one = |s: &str| s.to_string();
        // Single non-fixed delegates exactly.
        assert_eq!(
            query_grams_multi(&[one("NEEDLE_ALPHA")], false),
            query_grams("NEEDLE_ALPHA")
        );
        // Fixed uses literal windows, even where regex parse would bail.
        let g = query_grams_multi(&[one("foo*bar")], true).unwrap();
        assert_eq!(g.len(), 1);
        assert!(g[0].contains(&gram_pack(b"foo")));
        assert!(g[0].contains(&gram_pack(b"bar")));
        // Multi unions branches; any gram-less pattern forces a full scan.
        let u = query_grams_multi(&[one("NEEDLE_ALPHA"), one("needle_1")], false).unwrap();
        assert_eq!(u.len(), 2);
        assert!(query_grams_multi(&[one("NEEDLE_ALPHA"), one("a|b")], false).is_none());
        // Empty/short fixed patterns hold no trigram: full scan (an empty
        // pattern matches every line, so pruning would false-negative).
        assert!(query_grams_multi(&[one("")], true).is_none());
        assert!(query_grams_multi(&[one("ab")], true).is_none());
    }

    #[test]
    fn matchflags_pattern_lines() {
        let v = |b: &[u8]| split_pattern_lines(b);
        assert!(v(b"").is_empty());
        assert_eq!(v(b"a\n"), vec!["a"]);
        // Interior empties kept (match-all); trailing artifact dropped.
        assert_eq!(v(b"a\n\nb\n"), vec!["a", "", "b"]);
        assert_eq!(v(b"\n"), vec![""]);
        assert_eq!(v(b"a\r\nb\r\n"), vec!["a", "b"]);
        assert_eq!(v(b"a\rb"), vec!["a\rb"]);
    }

    #[test]
    fn matchflags_matcher_word_fixed() {
        // Word bounds via the searcher core (rg 15.1.0 shapes: foo-bar yes,
        // foobar/foo_bar no).
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
        // Fixed treats metachars literally.
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
        // Same through the cached twin (serve path).
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
        // -m keeps file order (first m).
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
        // Every single byte 0x00-0x7F standalone.
        for b in 0u8..=0x7Fu8 {
            check_str(&char::from_u32(b as u32).unwrap().to_string());
        }
        // Every control/quote/backslash embedded in text.
        let mut specials: Vec<char> = (0u8..0x20).map(|b| b as char).collect();
        specials.push('"');
        specials.push('\\');
        for c in &specials {
            check_str(&format!("a{c}b"));
            check_str(&format!("{c}lead"));
            check_str(&format!("trail{c}"));
        }
        // Full pair matrix over specials (byte-identical gate).
        for a in &specials {
            for b in &specials {
                check_str(&format!("{a}{b}"));
                check_str(&format!("x{a}y{b}z"));
            }
        }
        // Must-NOT-escape: DEL, high bytes via multibyte, slashes.
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
        // Hit-level sweep: lines x scores x tricky strings. Floats stay on
        // the serde path (ryu); this locks byte-identity including score.
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
        // Every line of the real bench corpus as `text`, every file path as
        // `path`: the differential check over actual emission bytes.
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
                // Spot Hit-level check per file: first line only keeps it fast.
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
