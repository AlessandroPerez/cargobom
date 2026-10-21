// impls written on type aliases: the context names the types they stand for
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256, Sha512};

pub trait Seal {
    fn seal(&self, msg: &[u8]) -> Vec<u8>;
}
impl Seal for Aes256Gcm {
    fn seal(&self, msg: &[u8]) -> Vec<u8> {
        self.encrypt(Nonce::from_slice(&[0u8; 12]), msg).unwrap_or_default()
    }
}

pub trait Fingerprint {
    fn fingerprint(d: &[u8]) -> usize;
}
impl Fingerprint for Sha256 {
    fn fingerprint(d: &[u8]) -> usize {
        Sha256::digest(d).len()
    }
}
impl Fingerprint for Sha512 {
    fn fingerprint(d: &[u8]) -> usize {
        Sha512::digest(d).len()
    }
}

pub fn run(d: &[u8]) -> usize {
    let c = Aes256Gcm::new_from_slice(&[1u8; 32]).unwrap();
    c.seal(d).len() + <Sha256 as Fingerprint>::fingerprint(d) + <Sha512 as Fingerprint>::fingerprint(d)
}
