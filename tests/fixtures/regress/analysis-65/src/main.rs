// round 11 regress (audit 10 probe c2): container members across functions: labels
use ring::digest::{digest, Algorithm as Digest, SHA256, SHA384};
use std::collections::HashMap;

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn fill2(m: &mut HashMap<u8, &'static Digest>) { m.insert(1, &SHA256); m.insert(2, &SHA384); }
fn make2() -> Vec<&'static Digest> { vec![&SHA256, &SHA384] }
fn read(m: &HashMap<u8, &'static Digest>, d: &[u8]) { let _ = digest(m[&1], d); }

fn main() {
    let d = arg(0).into_bytes();
    let mut m = HashMap::new();
    fill2(&mut m);
    let _ = digest(m[&1], &d);
    let v = make2();
    let _ = digest(v[0], &d);
    let mut m2 = HashMap::new();
    m2.insert(1u8, &SHA256);
    m2.insert(2u8, &SHA384);
    read(&m2, &d);
}
