use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, EcdsaSigningAlgorithm, KeyPair, UnparsedPublicKey};

fn signing_alg() -> &'static EcdsaSigningAlgorithm {
    &signature::ECDSA_P256_SHA256_FIXED_SIGNING
}

fn new_key(alg: &'static EcdsaSigningAlgorithm, rng: &SystemRandom) -> EcdsaKeyPair {
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, rng).unwrap();
    EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), rng).unwrap()
}

fn issue(alg: &'static EcdsaSigningAlgorithm, msg: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let rng = SystemRandom::new();
    let kp = new_key(alg, &rng);
    let sig = kp.sign(&rng, msg).unwrap();
    (kp.public_key().as_ref().to_vec(), sig.as_ref().to_vec())
}

fn main() {
    let msg = b"interprocedural";
    let (pk, sig) = issue(signing_alg(), msg);
    let ok = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &pk).verify(msg, &sig);
    println!("{}", ok.is_ok());
}
