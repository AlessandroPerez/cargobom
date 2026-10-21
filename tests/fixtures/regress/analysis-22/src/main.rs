// aws-lc-rs (fourth audit round): `verify_sig`, the current verification API (`verify` is
// deprecated); a digest context's `finish`; aws-lc-rs's own alias of a composite descriptor
// (`unstable::signature::MLDSA_44_SIGNING` is `ML_DSA_44_SIGNING`, which names `ML_DSA_44`)
use aws_lc_rs::digest;
use aws_lc_rs::signature::{self, ParsedPublicKey, UnparsedPublicKey, VerificationAlgorithm};

fn main() {
    let a = std::env::args().nth(1).unwrap_or_default().into_bytes();
    // Ed25519 verify
    let _ = signature::ED25519.verify_sig(&a, b"msg", &a);
    // ECDSA-P-256-SHA-256 verify
    let p = ParsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, &a).unwrap();
    let _ = p.verify_sig(b"msg", &a);
    // RSA-PSS-SHA-256 verify
    let u = UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA256, &a);
    let _ = u.verify(b"msg", &a);
    // SHA-384 digest (of the empty message)
    let ctx = digest::Context::new(&digest::SHA384);
    let d = ctx.finish();
    // ML-DSA-44 keygen and sign
    let kp = signature::PqdsaKeyPair::generate(&aws_lc_rs::unstable::signature::MLDSA_44_SIGNING)
        .unwrap();
    let mut sig = vec![0u8; 4000];
    let _ = kp.sign(b"msg", &mut sig);
    println!("{}", d.as_ref().len());
}
