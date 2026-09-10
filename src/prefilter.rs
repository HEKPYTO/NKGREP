//! Candidate prefilter for ranked queries (plan C, LoopC).
//!
//! Posting lists are sorted ascending unique file ids: `cmd_index` assigns
//! ids sequentially and pushes each file once per trigram, and the binary
//! codec round-trips lists verbatim (LoopB contract). All set ops below are
//! therefore linear two-pointer merges over sparse id arrays — no hashing,
//! no per-posting allocation. Scoring is deferred until after pruning so
//! pruned files cost no float work. Sort order is verified with
//! `debug_assert!`; a violated invariant is a bug, never silently absorbed.

/// Intersect two sorted id slices into `out` (cleared first).
pub fn intersect_sorted_into(a: &[u32], b: &[u32], out: &mut Vec<u32>) {
    out.clear();
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.len() && j < b.len() {
        let (x, y) = (a[i], b[j]);
        if x == y {
            out.push(x);
            i += 1;
            j += 1;
        } else if x < y {
            i += 1;
        } else {
            j += 1;
        }
    }
}

/// Union two sorted id slices into `out` (cleared first, deduped).
pub fn union_sorted_into(a: &[u32], b: &[u32], out: &mut Vec<u32>) {
    out.clear();
    out.reserve(a.len() + b.len());
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.len() && j < b.len() {
        let (x, y) = (a[i], b[j]);
        if x == y {
            out.push(x);
            i += 1;
            j += 1;
        } else if x < y {
            out.push(x);
            i += 1;
        } else {
            out.push(y);
            j += 1;
        }
    }
    out.extend_from_slice(&a[i..]);
    out.extend_from_slice(&b[j..]);
}

/// Intersect N sorted posting lists, smallest first; returns sorted unique
/// ids. Empty input or any empty list yields empty output.
pub fn intersect_all(lists: &mut Vec<&[u32]>) -> Vec<u32> {
    if lists.is_empty() {
        return vec![];
    }
    lists.sort_by_key(|l| l.len());
    #[cfg(debug_assertions)]
    for l in lists.iter() {
        debug_assert!(l.windows(2).all(|w| w[0] < w[1]));
    }
    let mut acc: Vec<u32> = lists[0].to_vec();
    let mut tmp: Vec<u32> = Vec::new();
    for l in &lists[1..] {
        intersect_sorted_into(&acc, l, &mut tmp);
        std::mem::swap(&mut acc, &mut tmp);
        if acc.is_empty() {
            break;
        }
    }
    acc
}
