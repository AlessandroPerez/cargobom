use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, EcdsaSigningAlgorithm, KeyPair, UnparsedPublicKey};
use ring::signature::VerificationAlgorithm;

trait Suite {
    fn signer(&self) -> &'static EcdsaSigningAlgorithm;
    fn verifier(&self) -> &'static dyn VerificationAlgorithm;
}

struct Gov;

impl Suite for Gov {
    fn signer(&self) -> &'static EcdsaSigningAlgorithm {
        &signature::ECDSA_P384_SHA384_ASN1_SIGNING
    }
    fn verifier(&self) -> &'static dyn VerificationAlgorithm {
        &signature::ECDSA_P384_SHA384_ASN1
    }
}

fn main() {
    let suite: Box<dyn Suite> = Box::new(Gov);
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(suite.signer(), &rng).unwrap();
    let kp = EcdsaKeyPair::from_pkcs8(suite.signer(), pkcs8.as_ref(), &rng).unwrap();
    let msg = b"dyn";
    let sig = kp.sign(&rng, msg).unwrap();
    let pk = UnparsedPublicKey::new(suite.verifier(), kp.public_key().as_ref());
    println!("{}", pk.verify(msg, sig.as_ref()).is_ok());
}
