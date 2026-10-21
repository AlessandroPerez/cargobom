use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use std::collections::BTreeMap;

type Claims = BTreeMap<String, u64>;

fn token_alg() -> Algorithm {
    Algorithm::EdDSA
}

fn sign_claims(alg: Algorithm, claims: &Claims) -> String {
    let key = EncodingKey::from_ed_pem(include_bytes!("ed.pem")).unwrap();
    encode(&Header::new(alg), claims, &key).unwrap()
}

fn issue(alg: Algorithm, sub: u64) -> String {
    let claims = Claims::from([("sub".to_string(), sub), ("exp".to_string(), 4_000_000_000)]);
    sign_claims(alg, &claims)
}

fn verify(alg: Algorithm, token: &str) -> u64 {
    let key = DecodingKey::from_ed_pem(include_bytes!("ed_pub.pem")).unwrap();
    decode::<Claims>(token, &key, &Validation::new(alg)).unwrap().claims["sub"]
}

fn main() {
    let alg = token_alg();
    let token = issue(alg, 7);
    println!("{}", verify(alg, &token));
}
