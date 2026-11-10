// jsonwebtoken 11 (as 10) keeps 9's API and the fields the boundary model reads
// (`Header.alg`, `Validation.algorithms`, the keys' family), with its cryptography behind a
// backend feature (aws-lc-rs here, or the RustCrypto crates): `encode` signs with the
// header's algorithm, `decode` verifies with the validation's, narrowed by the key's family,
// and a choice between two algorithms gives both.
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use std::collections::BTreeMap;

fn pick(strong: bool) -> Algorithm {
    if strong {
        Algorithm::HS512
    } else {
        Algorithm::HS256
    }
}

fn main() {
    let strong = std::env::args().count() > 1;
    let claims = BTreeMap::from([("sub", 42u64), ("exp", 4_000_000_000u64)]);
    let token = encode(&Header::new(Algorithm::HS384), &claims, &EncodingKey::from_secret(b"k3y")).unwrap();
    let data = decode::<BTreeMap<String, u64>>(
        &token,
        &DecodingKey::from_secret(b"k3y"),
        &Validation::new(Algorithm::HS384),
    );
    let alg = pick(strong);
    let second = encode(&Header::new(alg), &claims, &EncodingKey::from_secret(b"k3y")).unwrap();
    println!("{} {}", data.unwrap().claims["sub"], second.len());
}
