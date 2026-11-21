// PQClean's ML-DSA behind pqcrypto-mldsa: free functions in a module per parameter set, a
// signature attached to its message (`sign`, `open`) or detached, with a context string too;
// the sizes of a set's keys and signatures are constants, a signature's bytes an encoding.
use pqcrypto_mldsa::{mldsa44, mldsa87};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

fn main() {
    let msg = b"post-quantum";
    let (pk, sk) = mldsa87::keypair();
    let sig = mldsa87::detached_sign(msg, &sk);
    let ok = mldsa87::verify_detached_signature(&sig, msg, &pk).is_ok();

    let (pk2, sk2) = mldsa44::keypair();
    let signed = mldsa44::sign_ctx(msg, b"ctx", &sk2);
    let stored = mldsa44::PublicKey::from_bytes(pk2.as_bytes()).unwrap();
    let opened = mldsa44::open_ctx(&signed, b"ctx", &stored).is_ok();

    let sizes = mldsa87::signature_bytes() + pqcrypto_mlkem::mlkem768::ciphertext_bytes();
    println!("{ok} {opened} {} {sizes}", sig.as_bytes().len());
}
