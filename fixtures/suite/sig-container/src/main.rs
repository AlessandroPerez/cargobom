use ring::signature::{self, Ed25519KeyPair, KeyPair, UnparsedPublicKey, VerificationAlgorithm};

fn main() {
    let verifiers: Vec<&'static dyn VerificationAlgorithm> =
        vec![&signature::ECDSA_P384_SHA384_ASN1, &signature::ED25519];
    let keys: Vec<Ed25519KeyPair> = (1u8..=2)
        .map(|i| Ed25519KeyPair::from_seed_unchecked(&[i; 32]).unwrap())
        .collect();
    let msg = b"container";
    let sig = keys[1].sign(msg);
    let pk = UnparsedPublicKey::new(verifiers[1], keys[1].public_key().as_ref());
    println!("{}", pk.verify(msg, sig.as_ref()).is_ok());
}
