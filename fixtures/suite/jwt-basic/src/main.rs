use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use std::collections::BTreeMap;

fn main() {
    let claims = BTreeMap::from([("sub", 42u64), ("exp", 4_000_000_000u64)]);
    let header = Header::new(Algorithm::HS256);
    let token = encode(&header, &claims, &EncodingKey::from_secret(b"k3y")).unwrap();
    let validation = Validation::new(Algorithm::HS256);
    let data = decode::<BTreeMap<String, u64>>(&token, &DecodingKey::from_secret(b"k3y"), &validation);
    println!("{}", data.unwrap().claims["sub"]);
}
