// The walk and naming (second audit round): cyclic statics, a dependency's const, generated
// code, closures reached through the standard library.
use ring::digest::{SHA256, digest};

include!(concat!(env!("OUT_DIR"), "/gen.rs"));

// W1: N1 first (its value points at N2 before SHA-256), then N2, which leads to SHA-256
// through N1: both must lead to it, whichever was looked at first
fn w1(d: &[u8]) -> usize {
    digest(dep::N1.alg.unwrap(), d).as_ref().len() + digest(dep::N2.next.alg.unwrap(), d).as_ref().len()
}

// W2: a dependency's const and static naming ring statics
fn w2(d: &[u8]) -> usize {
    digest(dep::ALG_C, d).as_ref().len() + digest(dep::ALG_S, d).as_ref().len()
}

// W4: a closure called through generic standard-library code: its instantiation chain passes
// through calls without a position, which are named without one
fn w4(ds: &[&[u8]]) -> usize {
    ds.iter().map(|d| digest(&SHA256, d).as_ref().len()).sum()
}

fn main() {
    println!("{} {} {} {}", w1(b"a"), w2(b"b"), gen_hash(&[b"c"]), w4(&[b"d"]));
}
