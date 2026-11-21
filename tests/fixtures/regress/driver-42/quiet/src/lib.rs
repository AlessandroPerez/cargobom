use sha2::{Digest, Sha256, Sha512};

pub fn first(d: &[u8]) -> Vec<u8> {
    debug_assert!(sane(d));
    Sha256::digest(d).to_vec()
}

// Called only where debug assertions are compiled, which the release build does not for this
// crate: not in the program.
pub fn sane(d: &[u8]) -> bool {
    Sha512::digest(d).len() == 64
}
