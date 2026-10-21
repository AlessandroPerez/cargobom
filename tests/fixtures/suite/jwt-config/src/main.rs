use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use std::collections::BTreeMap;
use std::str::FromStr;

fn key_for(alg: Algorithm) -> EncodingKey {
    match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => EncodingKey::from_secret(b"config-secret"),
        Algorithm::ES256 => EncodingKey::from_ec_pem(include_bytes!("ec256.pem")).unwrap(),
        Algorithm::ES384 => EncodingKey::from_ec_pem(include_bytes!("ec384.pem")).unwrap(),
        Algorithm::EdDSA => EncodingKey::from_ed_pem(include_bytes!("ed.pem")).unwrap(),
        _ => EncodingKey::from_rsa_pem(include_bytes!("rsa.pem")).unwrap(),
    }
}

fn main() {
    let name = std::env::args().nth(1).unwrap_or_else(|| "HS256".to_string());
    let alg = Algorithm::from_str(&name).unwrap();
    let claims = BTreeMap::from([("exp", 4_000_000_000u64)]);
    let token = encode(&Header::new(alg), &claims, &key_for(alg)).unwrap();
    println!("{} {}", name, token.split('.').count());
}
