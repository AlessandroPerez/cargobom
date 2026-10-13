use sha2::{Digest, Sha256};

// a CRLF file
pub fn crlf(d: &[u8]) -> usize {
    let x = 1; let h = Sha256::digest(d);
    h.len() + x
}
