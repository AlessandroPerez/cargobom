// Argon2's parameters and parts, BLAKE3's modes. The output length of `hash_password_into` is
// its buffer's: A1 64 bytes (BLAKE2b-512 only), A2 a `Vec` of run-time length (a BLAKE2b of
// unknown length); `hash_password` with the default `Params` makes 32 bytes (A3: BLAKE2b-512 and
// BLAKE2b-256); the version named at `Argon2::new` (A4: 16); `Params::new(.., None)` leaves the
// output length unread (A5); `verify_password` hashes with the stored hash's (A6). BLAKE3's mode
// is its entry point's: `Hasher::new` unkeyed (B1), keyed (B2, B3), key derivation (B4).
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

fn a1() -> [u8; 64] {
    let mut out = [0u8; 64];
    Argon2::default().hash_password_into(b"password", b"fixed-salt-value", &mut out).unwrap();
    out
}

fn a2(n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    Argon2::default().hash_password_into(b"password", b"fixed-salt-value", &mut out).unwrap();
    out
}

fn a3(salt: &SaltString) -> String {
    Argon2::default().hash_password(b"password", salt).unwrap().to_string()
}

fn a4(salt: &SaltString) -> String {
    let a = Argon2::new(Algorithm::Argon2i, Version::V0x10, Params::default());
    a.hash_password(b"password", salt).unwrap().to_string()
}

fn a5(salt: &SaltString) -> String {
    let p = Params::new(65536, 3, 4, None).unwrap();
    let a = Argon2::new(Algorithm::Argon2d, Version::V0x13, p);
    a.hash_password(b"password", salt).unwrap().to_string()
}

fn a6(stored: &str) -> bool {
    let parsed = PasswordHash::new(stored).unwrap();
    Argon2::default().verify_password(b"password", &parsed).is_ok()
}

fn b1() -> blake3::Hash {
    let mut h = blake3::Hasher::new();
    h.update(b"data");
    h.finalize()
}

fn b2() -> blake3::Hash {
    let mut h = blake3::Hasher::new_keyed(&[7u8; 32]);
    h.update(b"data");
    h.finalize()
}

fn b3() -> blake3::Hash {
    blake3::keyed_hash(&[7u8; 32], b"data")
}

fn b4() -> [u8; 32] {
    blake3::derive_key("a151 2026-10-19 context", b"key material")
}

fn main() {
    let salt = SaltString::encode_b64(b"fixed-salt-value").unwrap();
    let n = std::hint::black_box(48);
    let h = a3(&salt);
    println!(
        "{} {} {} {} {} {} {}",
        a1()[0],
        a2(n).len(),
        a4(&salt).len(),
        a5(&salt).len(),
        a6(&h),
        b1(),
        b2() == b3()
    );
    println!("{}", b4()[0]);
}
