use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use base64::Engine;
use rand::{Rng, SeedableRng};

fn b64_env() {
    let raw = std::env::var("KEY_B64").unwrap();
    let key = base64::engine::general_purpose::STANDARD.decode(raw).unwrap();
    let _c = Aes256Gcm::new_from_slice(&key);
}

fn seeded() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let key: [u8; 32] = rng.gen();
    let c = Aes256Gcm::new_from_slice(&key).unwrap();
    let _ = c.encrypt(&Default::default(), &b"x"[..]);
}

fn main() {
    b64_env();
    seeded();
}
