// rsa 0.10: the keys are `PrivateKey` and `PublicKey` (0.9's `RsaPrivateKey`, `RsaPublicKey`),
// `Pss<D>` and `Oaep<D>` carry their hash in their type (a constructor named it in 0.9), and
// the keys have methods of their own with the scheme in the name (`pss_sign::<Sha384>`). The
// key types of the schemes (`pkcs1v15::SigningKey<Sha256>`) are as before.
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::sha2::{Digest, Sha256, Sha384};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{Oaep, PrivateKey, PublicKey, Pss};

fn main() {
    let msg = std::env::args().nth(1).unwrap_or_default();
    let msg = msg.as_bytes();
    let mut rng = rand::rng();
    let key = PrivateKey::new(&mut rng, 2048).unwrap();
    let public = PublicKey::from(&key);
    let signer = SigningKey::<Sha256>::new(key.clone());
    let sig = signer.sign_with_rng(&mut rng, msg);
    let ok1 = VerifyingKey::<Sha256>::new(public.clone()).verify(msg, &sig).is_ok();
    let digest = Sha256::digest(msg);
    let s2 = key.sign_with_rng(&mut rng, Pss::<Sha256>::new_with_salt(20), &digest).unwrap();
    let ok2 = public.verify(Pss::<Sha256>::new(), &digest, &s2).is_ok();
    let ct = public.encrypt(&mut rng, Oaep::<Sha256>::new(), msg).unwrap();
    let pt = key.decrypt(Oaep::<Sha256>::new(), &ct).unwrap();
    let s3 = key.pss_sign_with_rng::<Sha384, _>(&mut rng, msg).unwrap();
    let ok3 = public.pss_verify::<Sha384>(msg, &s3).is_ok();
    println!("{ok1} {ok2} {ok3} {} {}", sig.to_bytes().len(), pt.len());
}
