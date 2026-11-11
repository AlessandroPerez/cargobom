//! Closures called through `dyn Fn` objects: the algorithm is a parameter of the closure, and
//! the calls through the object pass it.

use ring::digest::{self, Algorithm, SHA256, SHA384, SHA512};

type Hash = Box<dyn Fn(&'static Algorithm, &[u8]) -> Vec<u8>>;

fn boxed() -> Hash {
    // SHA-256 and SHA-384, which `run` passes; beside an unknown, since where else the box may
    // be called from is not followed
    Box::new(|alg, data| digest::digest(alg, data).as_ref().to_vec())
}

fn by_ref(f: &dyn Fn(&'static Algorithm) -> Vec<u8>, out: &mut Vec<u8>) {
    out.extend(f(&SHA512));
}

pub fn run(input: &[u8]) -> Vec<u8> {
    let h = boxed();
    let mut out = h(&SHA256, input);
    out.extend(h(&SHA384, input));
    // a closure without captures, borrowed: SHA-512, which `by_ref` passes
    by_ref(&|alg| digest::digest(alg, b"fixed").as_ref().to_vec(), &mut out);
    out
}
