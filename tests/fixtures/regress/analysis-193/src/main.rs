// SLH-DSA, RustCrypto's slh-dsa: the parameter set is the key's type argument, a hash family
// with its sizes as type numbers (`Shake128f` is `Shake<U16, U34>`, `Sha2_256s` is
// `Sha2L35<U32, U47>`). `SigningKey::new(&mut rng)` makes a key; a signature's bytes are an
// encoding.
use slh_dsa::signature::{Keypair, Signer, Verifier};
use slh_dsa::{Sha2_256s, Shake128f, SigningKey};

fn main() {
    let mut rng = rand::thread_rng();
    let msg = b"post-quantum";
    let sk = SigningKey::<Shake128f>::new(&mut rng);
    let sig = sk.sign(msg);
    let vk = sk.verifying_key();
    let ok = vk.verify(msg, &sig).is_ok();

    let sk2 = SigningKey::<Sha2_256s>::slh_keygen_internal(&[1u8; 32], &[2u8; 32], &[3u8; 32]);
    let sig2 = sk2.try_sign_with_context(msg, b"ctx", None).unwrap();
    let ok2 = sk2
        .verifying_key()
        .try_verify_with_context(msg, b"ctx", &sig2)
        .is_ok();
    println!("{ok} {ok2} {}", sig2.to_bytes().len());
}
