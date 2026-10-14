// regress verify-18 (round 12, audit 11 M11: function pointers kept in containers, in a file with a `fn new`; audit 11 probe vq9)
use ring::digest::{digest, Algorithm, Digest, SHA256, SHA384, SHA512};
use std::collections::HashMap;

type F = fn(&'static Algorithm, &[u8]) -> Digest;

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

struct Reg { n: usize }
impl Reg { fn new() -> Reg { Reg { n: 1 } } }

fn main() {
    let d = arg(0).into_bytes();
    let mut map: HashMap<&str, F> = HashMap::new();
    map.insert("a", digest);
    let f = map.get("a").copied().unwrap();
    let _ = f(&SHA256, &d);
    let mut v: Vec<F> = Vec::new();
    v.push(digest);
    let g = v[0];
    let _ = g(&SHA384, &d);
    let r = Reg::new();
    let h: F = if r.n > 0 { digest } else { digest };
    let _ = h(&SHA512, &d);
}
