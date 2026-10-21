use ring::rand::SystemRandom;
use ring::signature::{self, KeyPair, RsaEncoding, RsaKeyPair, UnparsedPublicKey, VerificationAlgorithm};

const COMPAT: bool = false;

fn main() {
    let (padding, verifier): (&'static dyn RsaEncoding, &'static dyn VerificationAlgorithm) = if COMPAT {
        (&signature::RSA_PKCS1_SHA512, &signature::RSA_PKCS1_2048_8192_SHA512)
    } else if std::env::args().count() > 1 {
        (&signature::RSA_PSS_SHA256, &signature::RSA_PSS_2048_8192_SHA256)
    } else {
        (&signature::RSA_PKCS1_SHA256, &signature::RSA_PKCS1_2048_8192_SHA256)
    };
    let kp = RsaKeyPair::from_pkcs8(include_bytes!("rsa.pk8")).unwrap();
    let rng = SystemRandom::new();
    let msg = b"path";
    let mut sig = vec![0u8; kp.public().modulus_len()];
    kp.sign(padding, &rng, msg, &mut sig).unwrap();
    let pk = UnparsedPublicKey::new(verifier, kp.public_key().as_ref());
    println!("{}", pk.verify(msg, &sig).is_ok());
}
