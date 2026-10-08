use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::Aes256Gcm;
use anyhow::Context;
use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::Argon2;
use chacha20poly1305::XChaCha20Poly1305;
use ed25519_dalek::{Signer, SigningKey, Verifier};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512_224, Sha512_256};

fn hkdf_key() -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(None, &std::env::args().next().unwrap().into_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"my app info", &mut okm).unwrap();
    let c = Aes256Gcm::new_from_slice(&okm).unwrap();
    c.encrypt(&Default::default(), &b"x"[..]).unwrap()
}

fn env_key() -> anyhow::Result<()> {
    let k = std::env::var("KEY").context("KEY must be set")?;
    let _c = Aes256Gcm::new_from_slice(k.as_bytes());
    Ok(())
}

fn copied_key() {
    let mut key = [0u8; 32];
    key.copy_from_slice(&b"0123456789abcdef0123456789abcdef"[..]);
    let _c = Aes256Gcm::new_from_slice(&key);
}

fn xchacha() {
    let c = XChaCha20Poly1305::new_from_slice(&[1u8; 32]).unwrap();
    let _ = c.encrypt(&Default::default(), &b"x"[..]);
}

fn sha512_trunc(d: &[u8]) -> usize {
    let a = Sha512_256::digest(d);
    let b = Sha512_224::digest(d);
    let m = <Hmac<Sha512_256> as Mac>::new_from_slice(d).unwrap();
    a.len() + b.len() + m.finalize().into_bytes().len()
}

fn pbkdf(iters: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(b"pw", b"salt", iters, &mut out);
    out
}

fn argon_two_lines(pw: &[u8]) -> String {
    let argon2 = Argon2::default();
    let salt = SaltString::encode_b64(b"fixed-salt-value").unwrap();
    argon2.hash_password(pw, &salt).unwrap().to_string()
}

fn argon_into() -> [u8; 32] {
    let mut out = [0u8; 32];
    Argon2::default().hash_password_into(b"password", b"fixed-salt-value", &mut out).unwrap();
    out
}

fn scrypt_lit() -> [u8; 32] {
    let mut out = [0u8; 32];
    let p = scrypt::Params::recommended();
    scrypt::scrypt(b"password", b"fixed-salt", &p, &mut out).unwrap();
    out
}

fn ed() {
    let sk = SigningKey::generate(&mut OsRng);
    let sig = sk.sign(b"msg");
    let vk = sk.verifying_key();
    vk.verify(b"msg", &sig).unwrap();
}

fn rsa_osrng() {
    let _k = rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
}

fn aes_nonce16() {
    let c = aes_gcm::AesGcm::<aes_gcm::aes::Aes256, aes_gcm::aead::consts::U16>::new_from_slice(&[0u8; 32]).unwrap();
    let _ = c.encrypt(&Default::default(), &b"x"[..]);
}

fn main() {
    let n: u32 = std::env::args().count() as u32;
    hkdf_key();
    let _ = env_key();
    copied_key();
    xchacha();
    sha512_trunc(b"d");
    pbkdf(n);
    argon_two_lines(b"pw");
    argon_into();
    scrypt_lit();
    ed();
    rsa_osrng();
    aes_nonce16();
}
