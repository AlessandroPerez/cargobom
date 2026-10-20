// Argument origins and the knowledge base's roles (fourth audit round): appended secrets,
// counters, writes the origin search did not see, an `async` local overwritten after an
// `.await`, a nonce filled in a split buffer, generators lent to calls, and constructors and
// methods the knowledge base did not cover.
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, AeadInPlace, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version};
use argon2::password_hash::SaltString;
use ed25519_dalek::{DigestSigner, DigestVerifier, Signature, Signer, SigningKey, VerifyingKey};
use rand::Rng;
use sha2::{Digest, Sha512};
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};

fn appended() {
    // environment, not hard-coded
    let mut key = std::env::var("K").unwrap().into_bytes();
    key.extend_from_slice(b"pepper");
    let _ = Aes256Gcm::new_from_slice(&key);
    let mut salt = std::env::var("S").unwrap();
    salt.push_str("@example.org");
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(b"pw", salt.as_bytes(), 1000, &mut out);
}

fn counters(c: &Aes256Gcm) {
    // a counter: computed, not hard-coded
    let mut ctr = 0u64;
    for m in [b"a", b"b"] {
        ctr += 1;
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&ctr.to_be_bytes());
        let _ = c.encrypt(Nonce::from_slice(&nonce), m.as_ref());
    }
    let seq = AtomicU64::new(0);
    let mut n2 = [0u8; 12];
    n2[4..].copy_from_slice(&seq.fetch_add(1, Ordering::SeqCst).to_be_bytes());
    let _ = c.encrypt(Nonce::from_slice(&n2), b"m".as_ref());
}

struct Out<'a> {
    buf: &'a mut [u8],
}
fn fill_out(o: Out<'_>) {
    OsRng.fill_bytes(o.buf);
}

fn indirect() {
    // a cell's contents: computed
    let c = Cell::new([1u8; 32]);
    let mut fresh = [0u8; 32];
    OsRng.fill_bytes(&mut fresh);
    c.set(fresh);
    let _ = Aes256Gcm::new_from_slice(&c.get());
    // filled by a closure holding `&mut k1`: rng
    let mut k1 = [0u8; 32];
    let mut fill = || OsRng.fill_bytes(&mut k1);
    fill();
    let _ = Aes256Gcm::new_from_slice(&k1);
    // filled through a struct's `&mut`: rng (OsRng, in the program's fill_out)
    let mut k2 = [0u8; 32];
    fill_out(Out { buf: &mut k2 });
    let _ = Aes256Gcm::new_from_slice(&k2);
}

// overwritten after the `.await`: environment only
async fn load() -> bool {
    let mut key = [0u8; 32];
    let n = key.len();
    std::future::ready(()).await;
    key = std::env::var("K").unwrap().into_bytes()[..32].try_into().unwrap();
    Aes256Gcm::new_from_slice(&key).is_ok() && n == 32
}

fn buffers(cipher: &Aes256Gcm, msg: &[u8; 16]) {
    // [nonce | data]: the nonce part filled by the generator, rng only
    let mut data = vec![0u8; 12 + 16];
    let (nonce, in_out) = data.split_at_mut(12);
    in_out.copy_from_slice(msg);
    rand::thread_rng().try_fill_bytes(nonce).unwrap();
    let nonce = aes_gcm::aead::generic_array::GenericArray::clone_from_slice(nonce);
    let _ = cipher.encrypt_in_place_detached(&nonce, b"", in_out);
    // zeros whatever the length: hard-coded
    let buf = vec![0u8; 12 + msg.len()];
    let _ = cipher.encrypt(Nonce::from_slice(&buf[..12]), msg.as_ref());
    // a 16-byte part of a 32-byte literal: no byte count
    let material = [7u8; 32];
    let _ = aes_gcm::Aes128Gcm::new_from_slice(&material[..16]);
}

fn rsa_keys() {
    // the generator stays thread_rng; the second key is RSA-3072
    let mut rng = rand::thread_rng();
    let sk = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let pk = rsa::RsaPublicKey::from(&sk);
    let secret = std::env::var("SECRET").unwrap();
    let _ = pk.encrypt(&mut rng, rsa::Pkcs1v15Encrypt, secret.as_bytes());
    let _ = rsa::RsaPrivateKey::new(&mut rng, 3072);
    // the scheme is generated for, not a part of the key: RSA-PKCS1-1.5-SHA-256 keygen
    let _ = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::random(&mut rng, 2048);
}

fn ed25519ph() {
    let msg = b"m";
    let sk = SigningKey::generate(&mut OsRng);
    let vk: VerifyingKey = sk.verifying_key();
    let s1: Signature = sk.sign_prehashed(Sha512::new().chain_update(msg), Some(b"ctx")).unwrap();
    let _ = vk.verify_prehashed(Sha512::new().chain_update(msg), Some(b"ctx"), &s1);
    let s2: Signature = sk.sign_digest(Sha512::new().chain_update(msg));
    let _ = vk.verify_digest(Sha512::new().chain_update(msg), &s2);
    // Ed25519 itself, a key from hard-coded keypair bytes
    let kp = SigningKey::from_keypair_bytes(&KEYPAIR).unwrap();
    let _ = kp.sign(msg);
}

const KEYPAIR: [u8; 64] = [7u8; 64];

fn password_hashing() {
    let pw = std::env::var("PW").unwrap();
    let salt = SaltString::generate(&mut OsRng);
    // Argon2id-65536-3-4, Argon2id-19456-2-1, Argon2i-19456-2-1
    let a = Argon2::from(Params::new(65536, 3, 4, None).unwrap());
    let _ = a.hash_password(pw.as_bytes(), &salt);
    let b = Argon2::new(Algorithm::default(), Version::default(), Params::default());
    let _ = b.hash_password(pw.as_bytes(), &salt);
    let c = Argon2::new(Algorithm::Argon2i, Version::V0x13, Params::default());
    let _ = c.hash_password(pw.as_bytes(), &salt);
    // the salt of `hash_password_into_with_memory` is a role: hard-coded
    let mut out = [0u8; 32];
    let mut blocks = vec![argon2::Block::default(); 19456];
    let _ = Argon2::default().hash_password_into_with_memory(pw.as_bytes(), b"fixed-salt-123", &mut out, &mut blocks);
    // one scrypt asset, with the call's own parameters
    let params = scrypt::Params::new(15, 8, 1, 32).unwrap();
    let _ = scrypt::Scrypt.hash_password_customized(pw.as_bytes(), None, None, params, &salt);
    // BLAKE3 fed from a reader
    let mut h = blake3::Hasher::new();
    let _ = h.update_reader(std::io::stdin());
    let _ = h.finalize();
}

// the program's own generator is its code, not a source: computed
struct NotRandom;
impl RngCore for NotRandom {
    fn next_u32(&mut self) -> u32 {
        7
    }
    fn next_u64(&mut self) -> u64 {
        7
    }
    fn fill_bytes(&mut self, d: &mut [u8]) {
        d.fill(7)
    }
    fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), rand::Error> {
        d.fill(7);
        Ok(())
    }
}

fn own_rng() {
    let mut key = [0u8; 32];
    NotRandom.fill_bytes(&mut key);
    let _ = Aes256Gcm::new_from_slice(&key);
    let _: u8 = rand::thread_rng().r#gen();
}

fn main() {
    let cipher = Aes256Gcm::new(&Aes256Gcm::generate_key(OsRng));
    appended();
    counters(&cipher);
    indirect();
    let _ = load();
    buffers(&cipher, &[1u8; 16]);
    rsa_keys();
    ed25519ph();
    password_hashing();
    own_rng();
}
