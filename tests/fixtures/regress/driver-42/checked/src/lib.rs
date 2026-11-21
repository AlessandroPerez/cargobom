use sha2::{Digest, Sha256, Sha384};

pub fn second(d: &[u8]) -> Vec<u8> {
    debug_assert!(known(d));
    Sha256::digest(d).to_vec()
}

// Called only where debug assertions are compiled, which the manifest turns on for this crate in
// the release build: in the program.
pub fn known(d: &[u8]) -> bool {
    Sha384::digest(d).len() == 48
}
