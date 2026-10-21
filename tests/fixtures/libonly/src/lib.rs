//! rcbom fixture: a library with no `main`. Its public, monomorphic API is the entry point.
//! Expected findings, with their lines, are listed in ../expected.txt.
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// Public: reachable from the API.
pub fn fingerprint(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Public but generic: only a caller can instantiate it, so it is present, not reachable.
pub fn tag<M: Mac + hmac::digest::KeyInit>(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = <M as Mac>::new_from_slice(key).unwrap();
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

/// Public and monomorphic, calling the generic one: the HMAC-SHA-256 instance is reachable.
pub fn tag_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    tag::<Hmac<Sha256>>(key, data)
}

/// Private and never called: present only.
#[allow(dead_code)]
fn legacy(data: &[u8]) -> [u8; 16] {
    md5::compute(data).0
}
