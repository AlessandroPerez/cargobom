use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use std::collections::BTreeMap;

const INTEROP: bool = false;

fn main() {
    let alg = if INTEROP {
        Algorithm::HS256
    } else if std::env::args().count() > 1 {
        Algorithm::HS512
    } else {
        Algorithm::HS384
    };
    let claims = BTreeMap::from([("exp", 4_000_000_000u64)]);
    let token = encode(&Header::new(alg), &claims, &EncodingKey::from_secret(b"path-secret")).unwrap();
    let v = Validation::new(alg);
    let ok = decode::<BTreeMap<String, u64>>(&token, &DecodingKey::from_secret(b"path-secret"), &v).is_ok();
    println!("{ok}");
}
