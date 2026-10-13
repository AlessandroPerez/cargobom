use ring::pbkdf2;
use std::num::NonZeroU32;

fn strong_prf() -> pbkdf2::Algorithm {
    pbkdf2::PBKDF2_HMAC_SHA512
}

fn stretch(prf: pbkdf2::Algorithm, password: &[u8], out: &mut [u8]) {
    let rounds = NonZeroU32::new(210_000).unwrap();
    pbkdf2::derive(prf, rounds, b"user-salt", password, out);
}

fn enroll(prf: pbkdf2::Algorithm, password: &str) -> [u8; 64] {
    let mut hash = [0u8; 64];
    stretch(prf, password.as_bytes(), &mut hash);
    hash
}

fn main() {
    let stored = enroll(strong_prf(), "hunter2");
    println!("{:02x?}", &stored[..4]);
}
