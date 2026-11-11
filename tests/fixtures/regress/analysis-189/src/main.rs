use std::num::NonZeroU32;

use ring::pbkdf2;

const ROUNDS: NonZeroU32 = NonZeroU32::new(600_000).unwrap();

// both written at the call: PBKDF2-SHA-256-100000-32
fn at_the_call(password: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let rounds = NonZeroU32::new(100_000).unwrap();
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, rounds, b"salt at call", password, &mut out);
    out
}

// the count a constant: PBKDF2-SHA-512-600000-64
fn by_constant(password: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA512, ROUNDS, b"salt constant", password, &mut out);
    out
}

// the count the caller's: PBKDF2-SHA-384, no more
fn by_caller(password: &[u8], rounds: NonZeroU32) -> [u8; 48] {
    let mut out = [0u8; 48];
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA384, rounds, b"salt caller", password, &mut out);
    out
}

// the length a run-time value: PBKDF2-SHA-1, no more
fn by_length(password: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let rounds = NonZeroU32::new(4096).unwrap();
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA1, rounds, b"salt length", password, &mut out);
    out
}

// a verification against a stored value of unknown length: PBKDF2-SHA-256, no more
fn check(password: &[u8], stored: &[u8]) -> bool {
    pbkdf2::verify(pbkdf2::PBKDF2_HMAC_SHA256, ROUNDS, b"salt check", password, stored).is_ok()
}

fn main() {
    let input = std::env::args().nth(1).unwrap_or_default().into_bytes();
    let rounds = NonZeroU32::new(input.len() as u32 + 1).unwrap();
    let a = at_the_call(&input);
    let b = by_constant(&input);
    let c = by_caller(&input, rounds);
    let d = by_length(&input, input.len() + 16);
    println!("{:x?} {:x?} {:x?} {:x?} {}", a, &b[..4], &c[..4], d, check(&input, &a));
}
