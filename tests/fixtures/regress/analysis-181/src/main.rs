// A value a constructor made names the call it is passed to also when it reaches the call
// from another function: read from a field another function stored it in (`a.scheme.clone()`),
// or passed by the callers of the function (`sign_with`). Only when every value that reaches
// the call is such a constructor's and they agree: a field two constructors are stored in
// (`Two`) leaves the call at its family's name. And a verification of a password hash made in
// the same function hashes with the parameters that made it, whatever its own receiver is
// (`other.verify_password(pw, &hash)`); a hash parsed from input stays the family's.
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Pkcs1v15Sign, RsaPrivateKey};
use sha2::{Digest, Sha256, Sha384};

struct One {
    key: RsaPrivateKey,
    scheme: Pkcs1v15Sign,
}

struct Two {
    key: RsaPrivateKey,
    scheme: Pkcs1v15Sign,
}

fn key() -> RsaPrivateKey {
    RsaPrivateKey::from_pkcs8_pem(include_str!("rsa.pem")).unwrap()
}

fn one() -> One {
    One { key: key(), scheme: Pkcs1v15Sign::new::<Sha384>() }
}

fn two(alt: bool) -> Two {
    if alt {
        Two { key: key(), scheme: Pkcs1v15Sign::new::<Sha256>() }
    } else {
        Two { key: key(), scheme: Pkcs1v15Sign::new::<Sha384>() }
    }
}

fn sign_with(k: &RsaPrivateKey, scheme: Pkcs1v15Sign, h: &[u8]) -> Vec<u8> {
    k.sign(scheme, h).unwrap()
}

fn main() {
    let input = std::env::args().nth(1).unwrap_or_default();
    let h = Sha384::digest(input.as_bytes());
    let a = one();
    let s1 = a.key.sign(a.scheme.clone(), &h).unwrap();
    let b = two(input.is_empty());
    let s2 = b.key.sign(b.scheme.clone(), &h).unwrap();
    let s3 = sign_with(&a.key, Pkcs1v15Sign::new::<Sha384>(), &h);
    let salt = SaltString::encode_b64(b"fixed-salt-16byt").unwrap();
    let argon = Argon2::default();
    let hash = argon.hash_password(b"password", &salt).unwrap();
    let other = Argon2::new(Algorithm::Argon2i, Version::V0x13, Params::default());
    let ok1 = other.verify_password(b"password", &hash).is_ok();
    let ok2 = match PasswordHash::new(&input) {
        Ok(stored) => argon.verify_password(b"password", &stored).is_ok(),
        Err(_) => false,
    };
    println!("{} {} {} {ok1} {ok2}", s1.len(), s2.len(), s3.len());
}
