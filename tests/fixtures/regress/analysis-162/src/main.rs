// a crate the knowledge base models, at a version it does not cover: its operations are unknown
// algorithms with the reason, never dropped (md5 0.8's `Context::finalize`, ed25519-dalek 3's
// `sign` and `verify`); a streaming step (`consume`) is no operation
use ed25519_dalek::{Signer, SigningKey};
fn main() {
    let d = std::env::args().next().unwrap_or_default().into_bytes();
    let mut c = md5::Context::new();
    c.consume(&d);
    let _ = c.finalize(); // an unknown hash (MD5)
    let k = SigningKey::from_bytes(&[7u8; 32]);
    let s = k.sign(&d); // an unknown signature (Ed25519)
    let _ = k.verify(&d, &s); // an unknown signature (Ed25519)
}
