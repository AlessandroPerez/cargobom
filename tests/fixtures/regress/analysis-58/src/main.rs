// round 10: algorithms listed together in a `Validation` (`vec![..]`), one of another family than the key
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use std::collections::BTreeMap;

fn main() {
    let t = std::env::args().nth(1).unwrap_or_default();
    let rsa = DecodingKey::from_rsa_pem(include_bytes!("../Cargo.toml")).unwrap();
    let mut v = Validation::default();
    v.algorithms = vec![Algorithm::RS256, Algorithm::HS256];
    let _ = decode::<BTreeMap<String, u64>>(&t, &rsa, &v); // refused: unknown
    let mut w = Validation::default();
    w.algorithms = vec![Algorithm::RS256, Algorithm::RS384];
    let _ = decode::<BTreeMap<String, u64>>(&t, &rsa, &w); // RS256, RS384
}
