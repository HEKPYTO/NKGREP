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

pub fn intersect_all(lists: &mut Vec<&[u32]>) -> Vec<u32> {
    if lists.is_empty() {
        return vec![];
    }
    lists.sort_by_key(|l| l.len());
    for l in lists.iter() {
        if !l.windows(2).all(|w| w[0] < w[1]) {
            eprintln!("corrupt index: unsorted postings");
            std::process::exit(2);
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn merge_matches_hashset_model() {
        let cases: &[(&[u32], &[u32])] = &[
            (&[], &[]),
            (&[], &[1, 2]),
            (&[1, 2], &[]),
            (&[1, 3, 5], &[2, 4, 6]),
            (&[1, 2, 3], &[2, 3, 4]),
            (&[1, 2, 3, 4], &[1, 2, 3, 4]),
            (&[5], &[5]),
            (&[1, 100, 1000], &[2, 100, 999, 1000]),
        ];
        for (a, b) in cases {
            let mut inter = vec![];
            intersect_sorted_into(a, b, &mut inter);
            let set_a: HashSet<u32> = a.iter().cloned().collect();
            let set_b: HashSet<u32> = b.iter().cloned().collect();
            let mut model: Vec<u32> = set_a.intersection(&set_b).cloned().collect();
            model.sort_unstable();
            assert_eq!(inter, model, "intersect {a:?} {b:?}");
            let mut union = vec![];
            union_sorted_into(a, b, &mut union);
            let mut model: Vec<u32> = set_a.union(&set_b).cloned().collect();
            model.sort_unstable();
            assert_eq!(union, model, "union {a:?} {b:?}");
        }
    }
    #[test]
    fn intersect_all_smallest_first_exact() {
        let l1 = vec![1u32, 2, 3, 4, 5];
        let l2 = vec![2u32, 4];
        let l3 = vec![2u32, 3, 4, 9];
        let mut lists: Vec<&[u32]> = vec![&l1, &l3, &l2];
        assert_eq!(intersect_all(&mut lists), vec![2, 4]);
        let mut empty: Vec<&[u32]> = vec![];
        assert!(intersect_all(&mut empty).is_empty());
        let e = vec![];
        let mut with_empty: Vec<&[u32]> = vec![&l1, &e];
        assert!(intersect_all(&mut with_empty).is_empty());
    }
}
