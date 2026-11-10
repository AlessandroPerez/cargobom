// ed25519-dalek 3 over signature 3 (the same keys and calls as 2: `Signer::sign`,
// `Verifier::verify`, and the multipart variants signature 3 adds), a signing key made from a
// SHA-256 digest (sha2 0.11) as dufs derives its token key, and md5 0.8, whose `Context` ends
// with `finalize` (the former `compute`).
use ed25519_dalek::ed25519::signature::{MultipartSigner, Signer, Verifier};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

fn derived(user: &str) -> SigningKey {
    let mut h = Sha256::new();
    h.update(user.as_bytes());
    let hash = h.finalize();
    SigningKey::from_bytes(&hash.into())
}

fn main() {
    let msg = std::env::args().nth(1).unwrap_or_default();
    let key = SigningKey::generate(&mut rand::rng());
    let sig: Signature = key.sign(msg.as_bytes());
    let public: VerifyingKey = key.verifying_key();
    let ok1 = public.verify(msg.as_bytes(), &sig).is_ok();
    let ok2 = public.verify_strict(msg.as_bytes(), &sig).is_ok();
    let d = derived("user");
    let sig2 = d.multipart_sign(&[b"a", msg.as_bytes()]);
    let ok3 = d.verify(msg.as_bytes(), &sig2).is_ok();
    let mut ctx = md5::Context::new();
    ctx.consume(msg.as_bytes());
    let m1 = ctx.finalize();
    let m2 = md5::compute(msg.as_bytes());
    println!("{ok1} {ok2} {ok3} {:x} {:x}", m1, m2);
}
