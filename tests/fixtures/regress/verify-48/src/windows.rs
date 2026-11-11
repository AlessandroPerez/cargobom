use sha2::{Digest, Sha224};

pub fn socket_id(path: &[u8]) -> Vec<u8> {
    Sha224::digest(path).to_vec()
}
