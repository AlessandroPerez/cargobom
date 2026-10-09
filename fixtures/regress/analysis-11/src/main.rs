// Matching and provenance rules (second audit round).
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use cbc::cipher::{BlockEncryptMut, KeyIvInit, StreamCipher, block_padding::Pkcs7};
use rand::SeedableRng;
use rand::rngs::StdRng;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, UnboundKey};
use ring::hkdf;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

// P1: a key made of the caller's secret and a constant: it varies with the secret
fn p1(user: &[u8]) -> bool {
    let a = [user, b"0123456789abcdef"].concat();
    let b: Vec<u8> = b"0123456789abcdef".iter().chain(user.iter()).copied().collect();
    Aes256Gcm::new_from_slice(&a).is_ok() && Aes256Gcm::new_from_slice(&b).is_ok()
}

// P2: a nonce from a sequence number added to a constant base: it varies with the number
fn p2(c: &Aes256Gcm, seq: u64, m: &[u8]) -> Vec<u8> {
    let n = 1_000u64.wrapping_add(seq);
    let mut nb = [0u8; 12];
    nb[4..].copy_from_slice(&n.to_be_bytes());
    c.encrypt(Nonce::from_slice(&nb), m).unwrap()
}

// P3: a generator seeded with a constant makes predictable keys
fn p3() -> bool {
    let mut rng = StdRng::seed_from_u64(42);
    RsaPrivateKey::new(&mut rng, 2048).is_ok()
}

// M1: an AEAD key derived with HKDF and sealed in the same function: the seal is AES-256-GCM,
// the descriptor named where the key was made, not HKDF's further down the chain
fn m1(ikm: &[u8], msg: &[u8], n: [u8; 12]) -> Vec<u8> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, b"salt").extract(ikm);
    let okm = prk.expand(&[b"info"], &AES_256_GCM).unwrap();
    let key = LessSafeKey::new(UnboundKey::from(okm));
    let mut buf = msg.to_vec();
    key.seal_in_place_append_tag(ring::aead::Nonce::assume_unique_for_key(n), Aad::empty(), &mut buf)
        .unwrap();
    buf
}

// M2: a plain BLAKE3 hasher fed with a derived key stays a plain hash
fn m2(ikm: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&blake3::derive_key("a11 2026-10-08 context", ikm));
    *h.finalize().as_bytes()
}

// M3: a plain hasher returned by the program's own helper, which takes a keyed one: the
// helper's result is not its argument
fn pick(_k: blake3::Hasher) -> blake3::Hasher {
    blake3::Hasher::new()
}
fn m3(key: &[u8; 32], d: &[u8]) -> [u8; 32] {
    let mut h = pick(blake3::Hasher::new_keyed(key));
    h.update(d);
    *h.finalize().as_bytes()
}

// M4: OAEP padding built in a variable, then passed to encrypt: RSA-OAEP-SHA-256 throughout
fn m4(k: &RsaPublicKey, m: &[u8]) -> Vec<u8> {
    let padding = Oaep::new::<Sha256>();
    k.encrypt(&mut rand::thread_rng(), padding, m).unwrap()
}

// M5: AES used through the cbc and ctr modes: the aes crate provides the assets
fn m5(key: &[u8]) -> Vec<u8> {
    let enc = cbc::Encryptor::<aes::Aes128>::new_from_slices(&key[..16], &key[..16]).unwrap();
    let ct = enc.encrypt_padded_vec_mut::<Pkcs7>(b"msg");
    let mut c = ctr::Ctr128BE::<aes::Aes256>::new_from_slices(&key[..32], &key[..16]).unwrap();
    let mut buf = ct.clone();
    c.apply_keystream(&mut buf);
    buf
}

// M6: PBKDF2 with run-time iterations: the name stops at the hash, the output length stays a
// property
fn m6(pw: &[u8], rounds: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(pw, b"salt", rounds, &mut out);
    out
}

// M7: scrypt with its work factor in a `Params` built through `.ok()?`: the call is
// scrypt-32768-8-1-64 (it derives `out.len()` bytes, not the `Params` length), one asset with
// the constructor's
fn m7(pw: &[u8]) -> Option<[u8; 64]> {
    let p = scrypt::Params::new(15, 8, 1, 32).ok()?;
    let mut out = [0u8; 64];
    scrypt::scrypt(pw, b"m7-salt", &p, &mut out).ok()?;
    Some(out)
}

// M8: minisign's pattern, `Params` built in a helper from a run-time log_n and used elsewhere:
// one `scrypt` asset with r 8, p 1 and N unresolved, and dk_len 104 (the derivation), not also
// the 32 of the `Params` length, which only the password-hash API uses
fn m8_params(log_n: u8) -> scrypt::Params {
    scrypt::Params::new(log_n, 8, 1, 32).unwrap()
}

fn m8(pw: &[u8], log_n: u8) -> [u8; 104] {
    let mut out = [0u8; 104];
    scrypt::scrypt(pw, b"m8-salt", &m8_params(log_n), &mut out).unwrap();
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let c = Aes256Gcm::new_from_slice(args[0].as_bytes()).unwrap();
    println!("{} {:?} {}", p1(args[0].as_bytes()), p2(&c, args.len() as u64, b"m"), p3());
    let k = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    println!(
        "{:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?}",
        m1(b"ikm", b"m", [0u8; 12]),
        m2(b"ikm"),
        m3(&[3u8; 32], b"d"),
        m4(&RsaPublicKey::from(&k), b"m"),
        m5(args[0].as_bytes()),
        m6(b"pw", args.len() as u32),
        m7(args[0].as_bytes()),
        m8(b"pw", args.len() as u8)
    );
}
