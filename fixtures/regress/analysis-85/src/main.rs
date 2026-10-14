// round 12 regress (audit 11 probe co1): loops over containers holding values not followed, container labels across functions, dead callers
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
use std::collections::HashMap;

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

fn fill(m: &mut HashMap<u8, &'static Digest>) { m.insert(1, &SHA256); }
fn one() -> Vec<&'static Digest> { vec![&SHA384] }
fn h(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); }
#[allow(dead_code)]
fn dead(d: &[u8]) { let mut x: &'static Digest = &SHA1; (0..arg(9).len()).for_each(|_| x = &SHA512); h(x, d); }
fn loop_param(extra: &'static Digest, d: &[u8]) { for a in [&SHA256, extra] { let _ = digest(a, d); } }

fn main() {
    let d = arg(0).into_bytes();
    let mut x: &'static Digest = &SHA256;
    (0..arg(1).len()).for_each(|_| x = &SHA512);
    let arr = [x, &SHA384];
    for a in arr.iter() { let _ = digest(a, &d); }
    let _ = digest(arr[0], &d);
    let mut v = vec![&SHA384];
    if let Some(s) = v.first_mut().as_mut() { **s = &SHA512; }
    for a in &v { let _ = digest(a, &d); }
    let mut m = HashMap::new();
    fill(&mut m);
    let _ = digest(m[&1], &d);
    let _ = digest(one()[0], &d);
    h(&SHA256, &d);
    loop_param(&SHA384, &d);
    let mut it = v.iter();
    while let Some(a) = it.next() { let _ = digest(a, &d); }
    let mut w: Vec<&'static Digest> = Vec::new();
    w.push(&SHA256);
    w.iter_mut().for_each(|s| *s = &SHA1);
    for a in w.iter() { let _ = digest(a, &d); }
}
