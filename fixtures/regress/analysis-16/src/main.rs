// ring (third audit round): AEAD methods that encrypt or decrypt, their nonces, verification
// descriptors named but never used, PBKDF2 verify, HKDF, key agreement and signing; a
// descriptor's use is decided by the calls made with it, not by unrelated calls of the same name.
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, CHACHA20_POLY1305};
use ring::rand::{SecureRandom, SystemRandom};
use ring::{agreement, digest, hkdf, hmac, pbkdf2, signature};
use std::num::NonZeroU32;

// 1. open_in_place_separate_tag (ring 0.17): a decrypt with a hard-coded nonce
fn open_sep(key: &[u8], data: &mut [u8], tag: &[u8; 16]) -> usize {
    let k = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).unwrap());
    let t = aead::Tag::from(*tag);
    let r = k.open_in_place_separate_tag(Nonce::assume_unique_for_key([0u8; 12]), Aad::empty(), t, data, 0..);
    r.map(|p| p.len()).unwrap_or(0)
}

// 2. seal with chacha; nonce from SystemRandom fill (rng)
fn seal_chacha(key: &[u8], data: &mut Vec<u8>) {
    let k = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).unwrap());
    let mut n = [0u8; 12];
    SystemRandom::new().fill(&mut n).unwrap();
    k.seal_in_place_append_tag(Nonce::assume_unique_for_key(n), Aad::empty(), data).unwrap();
}

// 3. a verification descriptor named but never used for verifying; an HMAC verify elsewhere
fn named_only(pk: &[u8]) -> usize {
    let v = signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, pk.to_vec());
    v.as_ref().len()
}
fn hmac_verify(key: &[u8], msg: &[u8], tag: &[u8]) -> bool {
    let k = hmac::Key::new(hmac::HMAC_SHA384, key);
    hmac::verify(&k, msg, tag).is_ok()
}

// 4. PBKDF2 with ring: iterations constant; verify with a hard-coded salt
fn ring_pbkdf2(pw: &[u8]) -> bool {
    let mut out = [0u8; 32];
    let n = NonZeroU32::new(100_000).unwrap();
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA512, n, b"salt-salt", pw, &mut out);
    pbkdf2::verify(pbkdf2::PBKDF2_HMAC_SHA512, n, b"other-salt", b"hunter2", &out).is_ok()
}

// 5. ring digest Context with SHA-1; one-shot SHA-384
fn ring_digest(d: &[u8]) -> usize {
    let mut c = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
    c.update(d);
    c.finish().as_ref().len() + digest::digest(&digest::SHA384, d).as_ref().len()
}

// 6. HKDF: salt from a literal; expand to an AES-256-GCM key; HMAC context sign
fn ring_hkdf(secret: &[u8]) -> usize {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"fixed salt");
    let prk = salt.extract(secret);
    let okm = prk.expand(&[b"info"], &AES_256_GCM).unwrap();
    let key = UnboundKey::from(okm);
    let k2 = hmac::Key::new(hmac::HMAC_SHA256, b"literal hmac key");
    let mut ctx = hmac::Context::with_key(&k2);
    ctx.update(b"x");
    ctx.sign().as_ref().len() + key.algorithm().key_len()
}

// 7. key agreement (X25519) and ECDH P-256 ephemeral generation
fn ring_agree() -> usize {
    let rng = SystemRandom::new();
    let a = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap();
    let b = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
    let pb = b.compute_public_key().unwrap();
    let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, pb.as_ref().to_vec());
    agreement::agree_ephemeral(a, &peer, |m| m.len()).unwrap_or(0)
}

// 8. signing: Ed25519 generate_pkcs8 (keygen), ECDSA P-384 key pair sign, RSA sign PSS SHA-512
fn ring_sign(der: &[u8], msg: &[u8]) -> usize {
    let rng = SystemRandom::new();
    let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let kp = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let s1 = kp.sign(msg);
    let ek = signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P384_SHA384_FIXED_SIGNING, der, &rng).unwrap();
    let s2 = ek.sign(&rng, msg).unwrap();
    let rk = signature::RsaKeyPair::from_der(der).unwrap();
    let mut sig = vec![0u8; rk.public().modulus_len()];
    rk.sign(&signature::RSA_PSS_SHA512, &rng, msg, &mut sig).unwrap();
    s1.as_ref().len() + s2.as_ref().len()
}

// 9. an ECDSA verification descriptor kept, never used to verify; a P-256 key generated, never
// used in an agreement; an HMAC verify and an X25519 agreement elsewhere
fn keep(pk: &[u8]) -> usize {
    let v = signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, pk.to_vec());
    let rng = SystemRandom::new();
    let b = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
    v.as_ref().len() + b.compute_public_key().unwrap().as_ref().len()
}

// An HMAC tag verification and an X25519 agreement elsewhere.
fn other(key: &[u8], msg: &[u8], tag: &[u8]) -> bool {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    let rng = SystemRandom::new();
    let a = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap();
    let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, key.to_vec());
    let n = agreement::agree_ephemeral(a, &peer, |m| m.len()).unwrap_or(0);
    hmac::verify(&k, msg, tag).is_ok() && n > 0
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let k = args[0].as_bytes();
    let mut v = k.to_vec();
    open_sep(k, &mut v, &[0u8; 16]);
    seal_chacha(k, &mut v);
    named_only(k);
    hmac_verify(k, k, k);
    ring_pbkdf2(k);
    ring_digest(k);
    ring_hkdf(k);
    ring_agree();
    ring_sign(k, k);
    keep(k);
    other(k, k, k);
}
