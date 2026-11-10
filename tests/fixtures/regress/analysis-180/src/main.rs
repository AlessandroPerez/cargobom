// The elliptic-curve crates of the generation after 0.10 (ecdsa 0.17, elliptic-curve 0.14,
// p256 and p384 0.14): the same keys over the curve type (`SigningKey<NistP256>`,
// `EphemeralSecret<NistP256>`), signature 3's traits, and keys made through crypto-common's
// `Generate` (`generate_from_rng`), a key generation as `random` is.
use p256::ecdh::EphemeralSecret;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::Generate;

fn main() {
    let msg = std::env::args().nth(1).unwrap_or_default();
    let mut rng = rand::rng();
    let sk = SigningKey::generate_from_rng(&mut rng);
    let sig: Signature = sk.sign(msg.as_bytes());
    let vk = VerifyingKey::from(&sk);
    let ok = vk.verify(msg.as_bytes(), &sig).is_ok();
    let a = EphemeralSecret::generate_from_rng(&mut rng);
    let b = p256::SecretKey::generate_from_rng(&mut rng);
    let shared = a.diffie_hellman(&b.public_key());
    let k384 = p384::ecdsa::SigningKey::generate_from_rng(&mut rng);
    let s384: p384::ecdsa::Signature = k384.sign(msg.as_bytes());
    println!("{ok} {} {}", shared.raw_secret_bytes().len(), s384.to_bytes().len());
}
