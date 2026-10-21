// regress verify-27 (round 13, audit 12 M13/M14: values bound by destructuring patterns, `Option` combinators deciding the value by a closure, a function pointer stored in a struct field's map; verifier probes vr12, vr5)
use ring::digest::{digest, Algorithm, Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
use std::collections::HashMap;

type F = fn(&'static Algorithm, &[u8]) -> Digest;

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
struct Two { h: &'static Algorithm, l: &'static Algorithm }
struct Table { map: HashMap<u8, F> }
impl Table {
    fn new() -> Table { Table { map: HashMap::new() } }
}

fn main() {
    let d = arg(0).into_bytes();
    let [a, b] = [&SHA256, &SHA384];
    let _ = digest(a, &d);
    let _ = digest(b, &d);
    let Two { h, l } = Two { h: &SHA512, l: &SHA1 };
    let _ = digest(h, &d);
    let _ = digest(l, &d);
    let ((x, _), y) = ((&SHA1, 0u8), &SHA512);
    let _ = digest(x, &d);
    let _ = digest(y, &d);
    let (p, q) = (&SHA256, &SHA384);
    let _ = digest(p, &d);
    let _ = digest(q, &d);
    let v = vec![&SHA256];
    let i = arg(1).len();
    let _ = digest(v.get(i).map_or(&SHA512, |_| &SHA1), &d);
    let _ = digest(v.get(i).copied().unwrap_or(&SHA384), &d);
    let mut t = Table::new();
    t.map.insert(1, digest);
    if let Some(f) = t.map.get(&1) {
        let _ = f(&SHA384, &d);
    }
}
