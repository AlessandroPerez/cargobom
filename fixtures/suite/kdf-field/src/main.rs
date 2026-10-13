use ring::pbkdf2;
use std::num::NonZeroU32;

struct PasswordPolicy {
    prf: pbkdf2::Algorithm,
    iterations: NonZeroU32,
    key_len: usize,
}

fn policy() -> PasswordPolicy {
    PasswordPolicy {
        prf: pbkdf2::PBKDF2_HMAC_SHA384,
        iterations: NonZeroU32::new(100_000).unwrap(),
        key_len: 48,
    }
}

fn hash_password(p: &PasswordPolicy, pw: &str) -> Vec<u8> {
    let mut out = vec![0u8; p.key_len];
    pbkdf2::derive(p.prf, p.iterations, b"tenant-salt", pw.as_bytes(), &mut out);
    out
}

fn main() {
    let p = policy();
    println!("{:02x?}", &hash_password(&p, "swordfish")[..4]);
}
