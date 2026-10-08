use ring::digest::{digest, Algorithm, SHA256, SHA384, SHA512};

// L1: a public static table of descriptors
pub static ALGS: [&Algorithm; 1] = [&SHA512];

// L2: a public trait implemented for a public type
pub trait Hasher {
    fn hash(&self, d: &[u8]) -> usize;
}
pub struct H384;
impl Hasher for H384 {
    fn hash(&self, d: &[u8]) -> usize {
        digest(&SHA384, d).as_ref().len()
    }
}

// L3: a public fn the binary never calls
pub fn unused_by_bin(d: &[u8]) -> usize {
    digest(&SHA256, d).as_ref().len()
}

pub fn used_by_bin() -> usize {
    1
}
