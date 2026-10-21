use jsonwebtoken::{decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use std::collections::{BTreeMap, HashMap};

fn main() {
    let mut keyring: HashMap<&str, (Algorithm, &[u8])> = HashMap::new();
    keyring.insert("2023", (Algorithm::HS256, &b"old-secret"[..]));
    keyring.insert("2024", (Algorithm::HS512, &b"new-secret"[..]));

    let (alg, secret) = keyring["2024"];
    let mut header = Header::new(alg);
    header.kid = Some("2024".to_string());
    let claims = BTreeMap::from([("exp", 4_000_000_000u64)]);
    let token = encode(&header, &claims, &EncodingKey::from_secret(secret)).unwrap();

    let kid = decode_header(&token).unwrap().kid.unwrap();
    let (alg, secret) = keyring[kid.as_str()];
    let v = Validation::new(alg);
    let ok = decode::<BTreeMap<String, u64>>(&token, &DecodingKey::from_secret(secret), &v).is_ok();
    println!("{ok}");
}
