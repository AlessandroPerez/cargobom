use sha2::{Digest, Sha256, Sha384, Sha512};

#[link_section = ".text.grouped"]
pub fn used(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

#[link_section = ".text.grouped"]
pub fn unused(data: &[u8]) -> Vec<u8> {
    helper(data)
}

pub fn helper(data: &[u8]) -> Vec<u8> {
    Sha512::digest(data).to_vec()
}

pub fn other(data: &[u8]) -> Vec<u8> {
    Sha384::digest(data).to_vec()
}
