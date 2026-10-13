use ed25519_dalek::{Signer, SigningKey, Verifier};
use rand_core::OsRng;

fn main() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let msg = b"release v1.2.3";
    let sig = signing_key.sign(msg);
    let ok = signing_key.verifying_key().verify(msg, &sig).is_ok();
    println!("{ok}");
}
