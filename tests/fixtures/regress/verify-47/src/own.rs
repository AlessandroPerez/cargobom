//! A type of the program named like sha2's.

use sha2::Digest;

#[derive(Default)]
pub struct Sha256 {
    pub seen: usize,
}

impl Sha256 {
    pub fn finish(&self, data: &[u8]) -> Vec<u8> {
        // SHA-512/256, whatever the type is called
        sha2::Sha512_256::digest(&data[..self.seen.min(data.len())]).to_vec()
    }
}
