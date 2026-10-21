use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::digest::{digest, SHA256, SHA512_256};
use ring::{hkdf, pbkdf2, rand, signature};
use std::num::NonZeroU32;

fn hkdf_to_aead(ikm: &[u8]) -> LessSafeKey {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, b"salt").extract(ikm);
    let okm = prk.expand(&[b"info"], &AES_256_GCM).unwrap();
    LessSafeKey::new(UnboundKey::from(okm))
}

fn seal_digest(key: &LessSafeKey, msg: &[u8]) -> Vec<u8> {
    let mut buf = digest(&SHA256, msg).as_ref().to_vec();
    let nonce = Nonce::assume_unique_for_key([0u8; 12]);
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut buf).unwrap();
    buf
}

fn ring_pbkdf2(pw: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, NonZeroU32::new(100_000).unwrap(), b"salt", pw, &mut out);
    out
}

fn rsa3072(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_3072_8192_SHA384, pk).verify(msg, sig).is_ok()
}

fn ed_sign(pkcs8: &[u8]) -> Vec<u8> {
    let kp = signature::Ed25519KeyPair::from_pkcs8(pkcs8).unwrap();
    kp.sign(b"msg").as_ref().to_vec()
}

fn sha512_256(d: &[u8]) -> usize {
    digest(&SHA512_256, d).as_ref().len()
}

fn ed_gen() -> Vec<u8> {
    let rng = rand::SystemRandom::new();
    signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref().to_vec()
}

fn main() {
    let k = hkdf_to_aead(b"ikm");
    let _ = seal_digest(&k, b"m");
    let _ = ring_pbkdf2(b"pw");
    let _ = rsa3072(b"", b"", b"");
    let _ = ed_sign(&ed_gen());
    let _ = sha512_256(b"x");
}

#[allow(dead_code)]
pub fn ring_pbkdf2_key(pw: &[u8], salt: &[u8]) {
    let mut key = [0u8; 32];
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, NonZeroU32::new(100_000).unwrap(), salt, pw, &mut key);
    let _k = UnboundKey::new(&AES_256_GCM, &key);
}

#[allow(dead_code)]
pub fn ring_hkdf_key(ikm: &[u8], salt: &[u8]) {
    let mut key = [0u8; 32];
    hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(ikm).expand(&[b"ctx"], hkdf::HKDF_SHA256).unwrap().fill(&mut key).unwrap();
    let _k = UnboundKey::new(&AES_256_GCM, &key);
}
