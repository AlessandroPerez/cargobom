// Argument origins (second audit round): element writes, references, named constants.
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{KeyInit, OsRng};
use argon2::{Algorithm, Argon2, Params, Version};
use sha2::Sha256;

fn env_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    k[..std::env::args().count().min(32)].fill(1);
    k
}

// O1: two definitions of the key in one block: only the second reaches
#[allow(unused_assignments)]
fn o1() -> bool {
    let mut k = env_key();
    k = [2u8; 32];
    Aes256Gcm::new_from_slice(&k).is_ok()
}

// O2: an element write keeps the rest of the key (computed): not a hard-coded key
fn o2() -> bool {
    let mut key = env_key();
    key[31] = 1;
    Aes256Gcm::new_from_slice(&key).is_ok()
}

// O3: a random key, clamped: still random (the fill replaces the zero initialization)
fn o3() -> bool {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key[0] &= 248;
    key[31] &= 127;
    Aes256Gcm::new_from_slice(&key).is_ok()
}

// O4: an element write through a reference to the element
fn o4() -> bool {
    let mut key = env_key();
    let b = &mut key[3];
    *b = 9;
    Aes256Gcm::new_from_slice(&key).is_ok()
}

// O5: element-wise copy into a zero-initialized key: computed, not hard-coded
fn o5() -> bool {
    let src = env_key();
    let mut key = [0u8; 32];
    for i in 0..32 {
        key[i] = src[i];
    }
    Aes256Gcm::new_from_slice(&key).is_ok()
}

// O6: a field written after the whole struct: only the later constant reaches it
struct Cfg {
    key: [u8; 32],
    n: u32,
}
fn o6() -> bool {
    let mut c = Cfg { key: env_key(), n: 1 };
    c.key = [8u8; 32];
    Aes256Gcm::new_from_slice(&c.key).is_ok() && c.n > 0
}

// O7: an RNG fill through a reference to one of two keys: each may keep its constant
fn o7(c: bool) -> bool {
    let mut a = [7u8; 32];
    let mut b = [0u8; 32];
    let r: &mut [u8; 32] = if c { &mut a } else { &mut b };
    OsRng.fill_bytes(r);
    Aes256Gcm::new_from_slice(&a).is_ok() && Aes256Gcm::new_from_slice(&b).is_ok()
}

// O8: out-parameter through a reborrowed local reference: the fill replaces the zeros
fn o8() -> bool {
    let mut k = [0u8; 32];
    let r = &mut k;
    OsRng.fill_bytes(r);
    Aes256Gcm::new_from_slice(&k).is_ok()
}

// N1: PBKDF2 iterations from a named const, an associated const, a literal
const ITERATIONS: u32 = 600_000;
struct Rounds;
impl Rounds {
    const N: u32 = 210_000;
}
fn n1(pw: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(pw, salt, ITERATIONS, &mut out);
    let n = Rounds::N;
    pbkdf2::pbkdf2_hmac::<Sha256>(pw, salt, n, &mut out);
    pbkdf2::pbkdf2_hmac::<Sha256>(pw, salt, 100_000, &mut out);
    out
}

// N2: an RSA key size from a named const
const BITS: usize = 3072;
fn n2() -> bool {
    rsa::RsaPrivateKey::new(&mut OsRng, BITS).is_ok()
}

// N3: Argon2's variant as an enum value, directly and through a named const
const VARIANT: Algorithm = Algorithm::Argon2d;
fn n3(pw: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let a = Argon2::new(Algorithm::Argon2i, Version::V0x13, Params::default());
    a.hash_password_into(pw, b"saltsaltsalt", &mut out).unwrap();
    let b = Argon2::new(VARIANT, Version::V0x13, Params::default());
    b.hash_password_into(pw, b"saltsaltsalt", &mut out).unwrap();
    out
}

fn main() {
    println!("{} {} {} {} {} {} {} {}", o1(), o2(), o3(), o4(), o5(), o6(), o7(true), o8());
    println!("{:?} {} {:?}", n1(b"p", b"s"), n2(), n3(b"p"));
}
