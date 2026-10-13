use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256, Sha512};

pub fn seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key.into());
    cipher.encrypt(Nonce::from_slice(nonce), plaintext).unwrap()
}

pub fn content_id(data: &[u8]) -> [u8; 32] {
    hash_block(data)
}

fn hash_block(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

#[allow(dead_code)]
fn legacy_id(data: &[u8]) -> Vec<u8> {
    Sha512::digest(data).to_vec()
}
