//! A library's API (fourth audit round): the methods of a public type generic over a parameter
//! the crypto does not depend on (cookie's `PrivateJar<J>`) are reachable, as is a trait's default
//! method a public type takes; a long name keeps its method (`Sealer::<..>::seal_with_..`).
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use sha2::{Digest, Sha256, Sha384};

/// Generic over the parent jar only: AES-256-GCM reachable from the API
pub struct Jar<J> {
    pub parent: J,
    pub key: [u8; 32],
}

impl<J> Jar<J> {
    pub fn seal(&self, nonce: &[u8], msg: &[u8]) -> Vec<u8> {
        let c = Aes256Gcm::new_from_slice(&self.key).unwrap();
        c.encrypt(Nonce::from_slice(nonce), msg).unwrap()
    }
}

/// A trait with a default method a public type does not override: SHA-384 reachable
pub trait Hashy {
    fn hashy(&self, d: &[u8]) -> Vec<u8> {
        Sha384::digest(d).to_vec()
    }
    fn other(&self, d: &[u8]) -> Vec<u8>;
}

pub struct Pub;

impl Hashy for Pub {
    fn other(&self, d: &[u8]) -> Vec<u8> {
        Sha256::digest(d).to_vec()
    }
}

pub mod a_rather_long_module_name_for_the_example {
    use super::*;

    pub struct Sealer<T>(pub T);

    impl<T: AsRef<[u8]>> Sealer<T> {
        // the key is the first 16 bytes of a 32-byte literal: no byte count
        pub fn seal_with_a_descriptive_name(&self, nonce: &[u8]) -> Vec<u8> {
            let material = [7u8; 32];
            let c = Aes128Gcm::new_from_slice(&material[..16]).unwrap();
            c.encrypt(GenericArray::from_slice(nonce), self.0.as_ref()).unwrap()
        }
    }
}
