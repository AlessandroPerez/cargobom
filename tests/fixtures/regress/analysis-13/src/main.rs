// What a descriptor named in code stands for. A descriptor that permits one operation (ring's
// verification `ED25519`, `ECDSA_P256_SHA256_ASN1`) is evidence of that operation only where the
// program calls into ring to perform it.
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, Ed25519KeyPair, EdDSAParameters, KeyPair};

// rcgen's pattern: the verification algorithm is a tag of a signing scheme, compared but never
// used to verify. Ed25519 is keygen and sign; the static occurrences have no use, and the asset
// no `verify`
struct Scheme {
    tag: &'static EdDSAParameters,
}

static ED: Scheme = Scheme {
    tag: &signature::ED25519,
};

fn sign_tagged(scheme: &Scheme, msg: &[u8]) -> Vec<u8> {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    if std::ptr::eq(scheme.tag, &signature::ED25519) {
        kp.sign(msg).as_ref().to_vec()
    } else {
        kp.public_key().as_ref().to_vec()
    }
}

// a signing descriptor with its signing call: ECDSA-P-256-SHA-256, keygen and sign
fn sign_ecdsa(msg: &[u8]) -> Vec<u8> {
    let rng = SystemRandom::new();
    let alg = &signature::ECDSA_P256_SHA256_ASN1_SIGNING;
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
    let kp = EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), &rng).unwrap();
    kp.sign(&rng, msg).unwrap().as_ref().to_vec()
}

// a verification descriptor in a table nothing verifies with: ECDSA-P-384-SHA-384 named, with
// no use (the asset lists the knowledge base's functions, `verify`, as such)
static ACCEPTED: [&signature::EcdsaVerificationAlgorithm; 1] = [&signature::ECDSA_P384_SHA384_ASN1];

fn main() {
    let a = sign_tagged(&ED, b"m");
    let b = sign_ecdsa(b"m");
    println!("{} {} {}", a.len(), b.len(), ACCEPTED.len());
}
