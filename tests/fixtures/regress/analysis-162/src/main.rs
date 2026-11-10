// md5 0.8 and ed25519-dalek 3, first probed as versions the knowledge base did not cover (their
// operations unknown, with the reason; analysis-182 keeps that case, with rsa 0.10): covered
// since, md5 0.8's `Context::finalize` is MD5, ed25519-dalek 3's `sign` and `verify` Ed25519,
// and a streaming step (`consume`) is cited beside the call that ends the stream
use ed25519_dalek::{Signer, SigningKey};
fn main() {
    let d = std::env::args().next().unwrap_or_default().into_bytes();
    let mut c = md5::Context::new();
    c.consume(&d);
    let _ = c.finalize(); // MD5
    let k = SigningKey::from_bytes(&[7u8; 32]);
    let s = k.sign(&d); // Ed25519
    let _ = k.verify(&d, &s); // Ed25519
}
