// RustCrypto (third audit round): what a call's own parameters are, keys derived in BLAKE3's
// and HMAC's key modes, buffer-to-buffer and fallible cipher APIs, generators obtained through
// `Default`, RSA key generation, Argon2's variant, the program's own `Default`, keys in statics
// set at run time, AES and ChaCha20 used directly, Ed25519's hazmat API, OAEP's MGF1 hash.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, OnceLock};

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{
    BlockDecryptMut, BlockEncrypt, BlockEncryptMut, KeyInit as _, KeyIvInit, StreamCipher,
    block_padding::Pkcs7,
};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, Mac};
use rand::SeedableRng;
use rand::rngs::{OsRng, StdRng, ThreadRng};
use sha2::{Digest, Sha256, Sha512};

// A1: `verify_password` checks against the stored hash's own algorithm and costs, not the
// receiver's defaults (Argon2id 19456-2-1)
fn a1(pw: &[u8], stored: &str) -> bool {
    let parsed = PasswordHash::new(stored).unwrap();
    Argon2::default().verify_password(pw, &parsed).is_ok()
}

// A2: `hash_password_customized` with its own costs: Argon2id 65536-3-4
fn a2(pw: &[u8]) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(65536, 3, 4, None).unwrap();
    Argon2::default()
        .hash_password_customized(pw, None, None, params, &salt)
        .unwrap()
        .to_string()
}

// A3: the variant given to `new_with_secret` (argument 1): Argon2i
fn a3(secret: &[u8], pw: &[u8], salt: &[u8]) -> [u8; 32] {
    let h = Argon2::new_with_secret(secret, Algorithm::Argon2i, Version::V0x13, Params::default())
        .unwrap();
    let mut out = [0u8; 32];
    h.hash_password_into(pw, salt, &mut out).unwrap();
    out
}

// A4: a key from BLAKE3's key-derivation mode over a run-time secret, read through its XOF
// reader into a zeroed buffer: derived, not hard-coded
fn a4(secret: &[u8], n: &[u8]) -> Vec<u8> {
    let mut h = blake3::Hasher::new_derive_key("app 2024 aes key");
    h.update(secret);
    let mut key = [0u8; 32];
    h.finalize_xof().fill(&mut key);
    let c = Aes256Gcm::new_from_slice(&key).unwrap();
    c.encrypt(Nonce::from_slice(n), b"m".as_ref()).unwrap()
}

// A5: the same mode finalized whole: derived
fn a5(secret: &[u8], n: &[u8]) -> Vec<u8> {
    let mut h = blake3::Hasher::new_derive_key("app 2024 aes key");
    h.update(secret);
    let key = h.finalize();
    let c = Aes256Gcm::new_from_slice(key.as_bytes()).unwrap();
    c.encrypt(Nonce::from_slice(n), b"m".as_ref()).unwrap()
}

// A6: HMAC keyed by a constant label over a run-time secret: the tag is computed from both,
// not hard-coded
fn a6(secret: &[u8], n: &[u8]) -> Vec<u8> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(b"label").unwrap();
    m.update(secret);
    let key = m.finalize().into_bytes();
    let c = Aes256Gcm::new(&key);
    c.encrypt(Nonce::from_slice(n), b"m".as_ref()).unwrap()
}

// A7: CBC's buffer-to-buffer encryption and decryption, CTR's fallible keystream: uses
fn a7(key: &[u8; 16], iv: &[u8; 16], pt: &[u8], data: &mut [u8]) -> usize {
    let mut buf = [0u8; 64];
    let ct = cbc::Encryptor::<aes::Aes128>::new(key.into(), iv.into())
        .encrypt_padded_b2b_mut::<Pkcs7>(pt, &mut buf)
        .unwrap()
        .to_vec();
    let mut out = [0u8; 64];
    let pt2 = cbc::Decryptor::<aes::Aes128>::new(key.into(), iv.into())
        .decrypt_padded_b2b_mut::<Pkcs7>(&ct, &mut out)
        .unwrap();
    let mut c = ctr::Ctr128BE::<aes::Aes128>::new(key.into(), iv.into());
    pt2.len() + c.try_apply_keystream(data).is_ok() as usize
}

// A8: keys generated with `ThreadRng::default()` (rand's thread-local CSPRNG): not predictable
fn a8() -> usize {
    let mut rng = ThreadRng::default();
    let k = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let sk = ed25519_dalek::SigningKey::generate(&mut ThreadRng::default());
    rsa::traits::PublicKeyParts::size(&k) + sk.verifying_key().as_bytes().len()
}

// A9: RSA keys generated with an explicit exponent and as a PKCS#1 v1.5 signing key (keygen),
// an encryption padded from a generator seeded with a constant (predictable)
fn a9() -> usize {
    let e = rsa::BigUint::from(65537u32);
    let k1 = rsa::RsaPrivateKey::new_with_exp(&mut OsRng, 2048, &e).unwrap();
    let sk = rsa::pkcs1v15::SigningKey::<Sha256>::random(&mut OsRng, 3072).unwrap();
    let mut seeded = StdRng::seed_from_u64(42);
    let ct = rsa::RsaPublicKey::from(&k1)
        .encrypt(&mut seeded, rsa::Pkcs1v15Encrypt, b"m")
        .unwrap();
    ct.len() + format!("{sk:?}").len()
}

// A10: the program's own `Default` reads the key from the environment: not a fixed default
struct Config {
    key: Vec<u8>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            key: std::env::var("APP_KEY").unwrap().into_bytes(),
        }
    }
}

fn a10(msg: &[u8], n: &[u8]) -> Vec<u8> {
    let cfg = Config::default();
    let c = Aes256Gcm::new_from_slice(&cfg.key).unwrap();
    c.encrypt(Nonce::from_slice(n), msg).unwrap()
}

// A11: keys in statics set at run time (a `LazyLock` from the environment, a `OnceLock` from a
// file) and a nonce from a counter: none hard-coded
static LAZY_KEY: LazyLock<Vec<u8>> =
    LazyLock::new(|| std::env::var("APP_KEY").unwrap().into_bytes());
static ONCE_KEY: OnceLock<Vec<u8>> = OnceLock::new();
static COUNTER: AtomicU64 = AtomicU64::new(0);

fn a11(msg: &[u8], n: &[u8], c: &Aes256Gcm) -> usize {
    let lazy = Aes256Gcm::new_from_slice(&LAZY_KEY).unwrap();
    let once = Aes256Gcm::new_from_slice(ONCE_KEY.get().unwrap()).unwrap();
    let seq = COUNTER.fetch_add(1, Ordering::SeqCst);
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&seq.to_be_bytes());
    lazy.encrypt(Nonce::from_slice(n), msg).unwrap().len()
        + once.encrypt(Nonce::from_slice(n), msg).unwrap().len()
        + c.encrypt(Nonce::from_slice(&nonce), msg).unwrap().len()
}

// A12: AES-128 as a block cipher and ChaCha20 as a stream cipher, used directly with
// hard-coded keys: both assets, both crates used
fn a12(block: &mut [u8; 16]) {
    let c = aes::Aes128::new(GenericArray::from_slice(b"0123456789abcdef"));
    c.encrypt_block(GenericArray::from_mut_slice(block));
    let mut s = chacha20::ChaCha20::new(
        b"0123456789abcdef0123456789abcdef".into(),
        &[0u8; 12].into(),
    );
    s.apply_keystream(block);
}

// A13: Ed25519's hazmat API: an expanded secret key and a raw signature (Ed25519, not a
// SHA-512 setup)
fn a13(expanded: &[u8; 64], msg: &[u8]) -> ed25519_dalek::Signature {
    let esk = ed25519_dalek::hazmat::ExpandedSecretKey::from_bytes(expanded);
    let vk = ed25519_dalek::VerifyingKey::from(&esk);
    ed25519_dalek::hazmat::raw_sign::<Sha512>(&esk, msg, &vk)
}

// A14: Ed25519 signing and verification: curve25519-dalek's internal SHA-512 is not a use of
// the program's
fn a14(seed: [u8; 32]) -> bool {
    use ed25519_dalek::{Signer, Verifier};
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let sig = sk.sign(b"msg");
    sk.verifying_key().verify(b"msg", &sig).is_ok()
}

// A15: an HMAC key that is the SHA-256 of a secret (computed from the secret, not "or"), a
// digest finalized into a buffer (a use), CBC with PKCS#7 padding
fn a15(secret: &str) -> usize {
    let hashed = Sha256::new().chain_update(secret).finalize();
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&hashed).unwrap();
    mac.update(b"challenge");
    let _ = mac.finalize();
    let mut out = [0u8; 64];
    Sha512::new()
        .chain_update(secret.as_bytes())
        .finalize_into((&mut out).into());
    let iv = [7u8; 16];
    let ct = cbc::Encryptor::<aes::Aes256>::new(&hashed, &iv.into())
        .encrypt_padded_vec_mut::<Pkcs7>(b"data");
    ct.len() + out.len()
}

// A16: OAEP with MGF1 on the OAEP hash, and OAEP-SHA-256 with MGF1-SHA-1 (Java's
// OAEPWithSHA-256AndMGF1Padding): two schemes, whose ciphertexts do not decrypt under each other
fn a16(k: &rsa::RsaPrivateKey, msg: &[u8]) -> usize {
    let pk = rsa::RsaPublicKey::from(k);
    let a = pk
        .encrypt(&mut OsRng, rsa::Oaep::new::<Sha256>(), msg)
        .unwrap();
    let b = pk
        .encrypt(
            &mut OsRng,
            rsa::Oaep::new_with_mgf_hash::<Sha256, sha1::Sha1>(),
            msg,
        )
        .unwrap();
    a.len() + b.len()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let pw = a[0].as_bytes();
    let k = a[1].as_bytes();
    a1(
        pw,
        "$argon2i$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
    );
    a2(pw);
    a3(k, pw, k);
    a4(k, &k[..12]);
    a5(k, &k[..12]);
    a6(k, &k[..12]);
    let mut key = [0u8; 16];
    key.copy_from_slice(&k[..16]);
    let mut d = *b"data";
    a7(&key, &key, b"hello", &mut d);
    a8();
    a9();
    a10(b"m", &k[..12]);
    ONCE_KEY.set(std::fs::read("key.bin").unwrap()).unwrap();
    let c = Aes256Gcm::new_from_slice(&k[..32]).unwrap();
    a11(b"m", &k[..12], &c);
    let mut b = [0u8; 16];
    a12(&mut b);
    let mut expanded = [0u8; 64];
    expanded.copy_from_slice(&k[..64]);
    a13(&expanded, b"m");
    a14(k[..32].try_into().unwrap());
    println!("{}", a15(&a[2]));
    let k = rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    println!("{}", a16(&k, b"m"));
}
