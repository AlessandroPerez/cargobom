//! After rustls 0.21's `tls12` suites: statics written over several lines, each holding an
//! algorithm and a unit struct made a trait object; the object's methods use the key the caller
//! made for the suite's algorithm, or hand it on to the type that does. (apple-codesign's own
//! shape, a member reaching the call through the object from another function with the
//! coercion cited at the static's first line, is rustls's: this file keeps the table.)

use ring::aead;

pub trait AeadAlg: Send + Sync {
    fn decrypter(&self, key: aead::LessSafeKey) -> Box<dyn Decrypter>;
    fn seal(&self, key: &aead::LessSafeKey, data: &mut Vec<u8>);
}

pub trait Decrypter {
    fn decrypt(&self, nonce: [u8; 12], data: &mut Vec<u8>) -> usize;
}

pub struct Suite {
    pub aead_algorithm: &'static aead::Algorithm,
    pub aead_alg: &'static dyn AeadAlg,
}

pub enum Supported {
    Tls12(&'static Suite),
}

pub static SUITE_AES_256: Supported =
    Supported::Tls12(&Suite {
        aead_algorithm: &aead::AES_256_GCM,
        aead_alg: &AesGcm,
    });

pub static SUITE_CHACHA: Supported =
    Supported::Tls12(&Suite {
        aead_algorithm: &aead::CHACHA20_POLY1305,
        aead_alg: &ChaCha,
    });

pub struct AesGcm;
pub struct ChaCha;

struct GcmDecrypter {
    dec_key: aead::LessSafeKey,
}

struct ChaChaDecrypter {
    dec_key: aead::LessSafeKey,
}

impl AeadAlg for AesGcm {
    fn decrypter(&self, key: aead::LessSafeKey) -> Box<dyn Decrypter> {
        Box::new(GcmDecrypter { dec_key: key })
    }

    fn seal(&self, key: &aead::LessSafeKey, data: &mut Vec<u8>) {
        let nonce = aead::Nonce::assume_unique_for_key([0; 12]);
        key.seal_in_place_append_tag(nonce, aead::Aad::empty(), data).unwrap();
    }
}

impl AeadAlg for ChaCha {
    fn decrypter(&self, key: aead::LessSafeKey) -> Box<dyn Decrypter> {
        Box::new(ChaChaDecrypter { dec_key: key })
    }

    fn seal(&self, key: &aead::LessSafeKey, data: &mut Vec<u8>) {
        let nonce = aead::Nonce::assume_unique_for_key([1; 12]);
        key.seal_in_place_append_tag(nonce, aead::Aad::empty(), data).unwrap();
    }
}

impl Decrypter for GcmDecrypter {
    fn decrypt(&self, nonce: [u8; 12], data: &mut Vec<u8>) -> usize {
        self.dec_key
            .open_in_place(aead::Nonce::assume_unique_for_key(nonce), aead::Aad::empty(), data)
            .map_or(0, |plain| plain.len())
    }
}

impl Decrypter for ChaChaDecrypter {
    fn decrypt(&self, nonce: [u8; 12], data: &mut Vec<u8>) -> usize {
        self.dec_key
            .open_in_place(aead::Nonce::assume_unique_for_key(nonce), aead::Aad::empty(), data)
            .map_or(0, |plain| plain.len())
    }
}

pub fn open(suite: &Supported, key: &[u8], data: &mut Vec<u8>) -> usize {
    let Supported::Tls12(suite) = suite;
    let key = aead::LessSafeKey::new(aead::UnboundKey::new(suite.aead_algorithm, key).unwrap());
    suite.aead_alg.seal(&key, data);
    suite.aead_alg.decrypter(key).decrypt([0; 12], data)
}
