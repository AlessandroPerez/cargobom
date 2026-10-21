// audit 12 probe vf1: ordinary writes through a &mut binding (verifier)
use ring::digest::{digest, Algorithm as Digest, SHA256, SHA384, SHA512};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn main() {
    let d = arg(0).into_bytes();
    let mut a: &'static Digest = &SHA256;
    let r = &mut a;
    *r = &SHA512;
    let _ = digest(a, &d);
    let mut b: &'static Digest = &SHA256;
    if let Some(x) = Some(&mut b) { *x = &SHA384; }
    let _ = digest(b, &d);
}
