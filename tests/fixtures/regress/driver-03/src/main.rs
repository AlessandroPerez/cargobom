use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

// X1: StaticSecret from a hard-coded array, through `From` (the KB role names StaticSecret::from)
fn x1() -> [u8; 32] {
    let secret = StaticSecret::from([7u8; 32]);
    let public = PublicKey::from(&secret);
    *secret.diffie_hellman(&public).as_bytes()
}

// X2: a random secret from a by-value unit-struct RNG
fn x2() -> [u8; 32] {
    let secret = StaticSecret::random_from_rng(OsRng);
    *secret.diffie_hellman(&PublicKey::from([9u8; 32])).as_bytes()
}

// E1: Ed25519 signing key through TryFrom
fn e1(b: &[u8]) -> bool {
    ed25519_dalek::SigningKey::try_from(b).is_ok()
}

// K1: RSA key size from a local
fn k1() -> bool {
    let bits = 2048;
    rsa::RsaPrivateKey::new(&mut OsRng, bits).is_ok()
}

fn main() {
    println!("{:?} {:?} {} {}", x1(), x2(), e1(&[1u8; 32]), k1());
}
