use sha2::{Digest, Sha256};

// Two functions whose code is the same: optimised, they are one function in the binary, under
// both names.
pub fn first(d: &[u8]) -> Vec<u8> {
    Sha256::digest(d).to_vec()
}

pub fn second(d: &[u8]) -> Vec<u8> {
    Sha256::digest(d).to_vec()
}
