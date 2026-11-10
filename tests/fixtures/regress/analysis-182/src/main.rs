// What the knowledge base still does not cover is an operation of unknown algorithm with the
// reason, never dropped and never guessed: a hash of a crypto package it does not model
// (ripemd, through `Digest`); a MAC of one (cmac) over a cipher it does model, which is not
// that cipher's operation (`Cmac<Aes128>` is no AES-128 encryption); and a crate it models at
// a version it does not cover (rsa 0.10, whose keys and paddings are other types than 0.9's).
use cmac::{Cmac, Mac};
use ripemd::{Digest, Ripemd160};
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::PrivateKey;

fn main() {
    let data = std::env::args().nth(1).unwrap_or_default();
    let data = data.as_bytes();
    let d = Ripemd160::digest(data);
    let mut m = Cmac::<aes::Aes128>::new_from_slice(b"0123456789abcdef").unwrap();
    m.update(data);
    let tag = m.finalize().into_bytes();
    let mut rng = rand::rng();
    let key = PrivateKey::new(&mut rng, 2048).unwrap();
    let signer = SigningKey::<sha2::Sha256>::new(key);
    let sig = signer.sign_with_rng(&mut rng, data).to_vec();
    println!("{} {} {}", d.len(), tag.len(), sig.len());
}
