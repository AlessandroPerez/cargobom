// regress verify-15 (round 12, audit 11 M7: descriptors in statics and consts of another package of the build; audit 11 probe vq4)
use picklib::CALG as X;
use picklib::inner::DEEP;
use ring::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1};

const LOCAL: &ring::digest::Algorithm = &SHA1;

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

fn main() {
    let d = arg(0).into_bytes();
    let _ = digest(picklib::ALG, &d);
    let _ = digest(X, &d);
    let _ = digest(DEEP, &d);
    let i = arg(1).len() % 2;
    let _ = digest(picklib::TABLE[i], &d);
    let a = picklib::ALG;
    let _ = digest(a, &d);
    let _ = digest(LOCAL, &d);
}
