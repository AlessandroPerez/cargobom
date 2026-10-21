// regress verify-14 (round 12, audit 11 M7: descriptors in consts and statics of another file of the crate; audit 11 probe vq10)
mod algs;
use ring::digest::{digest, SHA256};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

fn main() {
    let d = arg(0).into_bytes();
    let _ = digest(algs::CHOSEN, &d);
    let _ = digest(algs::OTHER, &d);
    let _ = digest(&SHA256, &d);
}
