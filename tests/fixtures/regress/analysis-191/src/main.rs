// ML-DSA, RustCrypto's ml-dsa 0.1: the parameter set is the key's type argument. A key is
// generated (`Generate`), signs through `signature::Signer` and by the methods named after
// FIPS 204, and its public key verifies; a signature's and a public key's bytes are encodings,
// and a key read from its seed is setup (the method does not say the seed is fresh).
use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{EncodedSignature, Generate, MlDsa44, MlDsa65, MlDsa87, Signature, SigningKey};

fn stored(seed: &[u8; 32]) -> SigningKey<MlDsa87> {
    SigningKey::<MlDsa87>::from_seed(&(*seed).into())
}

fn main() {
    let msg = b"post-quantum";
    let sk = SigningKey::<MlDsa65>::generate();
    let sig = sk.sign(msg);
    let vk = sk.verifying_key();
    let ok = vk.verify(msg, &sig).is_ok();

    let enc: EncodedSignature<MlDsa65> = sig.encode();
    let back = Signature::<MlDsa65>::decode(&enc).is_some();

    let small = SigningKey::<MlDsa44>::generate();
    let det = small.expanded_key().sign_deterministic(msg, b"ctx").unwrap();
    let ok2 = small.verifying_key().verify_with_context(msg, b"ctx", &det);

    let old = stored(&[7u8; 32]);
    let pk = old.verifying_key().encode();
    println!("{ok} {back} {ok2} {}", pk.len());
}
