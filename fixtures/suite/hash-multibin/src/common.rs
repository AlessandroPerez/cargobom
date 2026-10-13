use sha2::{Digest, Sha384};

pub const LABEL: &str = "multibin";

pub fn manifest_digest(data: &[u8]) -> Vec<u8> {
    Sha384::digest(data).to_vec()
}
