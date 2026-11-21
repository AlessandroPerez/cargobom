// ML-DSA, ml-dsa 0.0.4: keys are made on the parameter set (`MlDsa65::key_gen`, its `KeyGen`
// trait; `key_gen_internal` from a seed), as a `KeyPair` of a signing and a verifying key.
use ml_dsa::signature::{Signer, Verifier};
use ml_dsa::{KeyGen, MlDsa65, MlDsa87, B32};

fn main() {
    let mut rng = rand::thread_rng();
    let msg = b"post-quantum";
    let kp = MlDsa65::key_gen(&mut rng);
    let sig = kp.signing_key().sign(msg);
    let ok = kp.verifying_key().verify(msg, &sig).is_ok();

    let seed = B32::default();
    let kp2 = MlDsa87::key_gen_internal(&seed);
    let sig2 = kp2.signing_key().sign_randomized(msg, b"", &mut rng).unwrap();
    let ok2 = kp2.verifying_key().verify_with_context(msg, b"", &sig2);
    let bytes = sig2.encode();
    println!("{ok} {ok2} {}", bytes.len());
}
