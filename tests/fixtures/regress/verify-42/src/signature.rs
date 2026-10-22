use crate::{public, Check};
use sha2::Digest;

impl Check for public::SkKey {
    fn check(&self, m: &[u8]) -> usize {
        sha2::Sha256::digest(m).len() // SHA-256
    }
}

pub struct Seed(pub [u8; 32]);

impl From<&Seed> for ed25519_dalek::SigningKey {
    fn from(s: &Seed) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&s.0) // Ed25519
    }
}
