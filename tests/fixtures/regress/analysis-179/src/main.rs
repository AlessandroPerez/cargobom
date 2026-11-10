// More of the generation after 0.10: sha3 0.11's hashes and SHAKE (structs of their own),
// blake2 0.11 (`Blake2b<OutSize>`, a struct over the output size), argon2 0.6 with its
// constructors and `hash_password_into`, bcrypt-pbkdf 0.11 and x25519-dalek 3.
use blake2::digest::consts::U32;
use blake2::digest::{ExtendableOutput, Update, XofReader};
use blake2::{Blake2b, Blake2b512, Blake2s256, Digest};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

fn main() {
    let data = std::env::args().nth(1).unwrap_or_default();
    let data = data.as_bytes();
    let d1 = sha3::Sha3_256::digest(data);
    let d2 = sha3::Sha3_512::digest(data);
    let mut shake = sha3::Shake256::default();
    shake.update(data);
    let mut out = [0u8; 40];
    shake.finalize_xof().read(&mut out);
    let d3 = Blake2b512::digest(data);
    let d4 = Blake2s256::digest(data);
    let d5 = Blake2b::<U32>::digest(data);
    let argon = argon2::Argon2::default();
    let mut k1 = [0u8; 32];
    argon.hash_password_into(data, b"saltsaltsalt", &mut k1).unwrap();
    let params = argon2::Params::new(8192, 3, 1, None).unwrap();
    let custom = argon2::Argon2::new(argon2::Algorithm::Argon2i, argon2::Version::V0x13, params);
    let mut k2 = [0u8; 24];
    custom.hash_password_into(data, b"saltsaltsalt", &mut k2).unwrap();
    let mut k3 = [0u8; 48];
    bcrypt_pbkdf::bcrypt_pbkdf(data, b"salt", 16, &mut k3).unwrap();
    let mine = EphemeralSecret::random_from_rng(&mut rand::rng());
    let fixed = StaticSecret::from([9u8; 32]);
    let shared = mine.diffie_hellman(&PublicKey::from(&fixed));
    println!(
        "{} {} {} {} {} {} {} {} {} {}",
        d1.len(), d2.len(), out.len(), d3.len(), d4.len(), d5.len(), k1.len(), k2.len(),
        k3.len(), shared.as_bytes().len()
    );
}
