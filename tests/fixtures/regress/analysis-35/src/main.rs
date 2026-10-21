// round 8 probe: jsonwebtoken's boundary model beyond the suite
use jsonwebtoken::{decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use std::collections::BTreeMap;

fn main() {
    let claims = BTreeMap::from([("exp", 4_000_000_000u64)]);
    // 1: the header's algorithm set after construction
    let mut h = Header::default();
    h.alg = Algorithm::HS384;
    let t1 = encode(&h, &claims, &EncodingKey::from_secret(b"k")).unwrap();
    // 2: the validation's algorithms set by assignment
    let mut v = Validation::default();
    v.algorithms = vec![Algorithm::HS384, Algorithm::HS512];
    let _ = decode::<BTreeMap<String, u64>>(&t1, &DecodingKey::from_secret(b"k"), &v);
    // 3: the algorithm the token names
    let alg = decode_header(&t1).unwrap().alg;
    let _ = decode::<BTreeMap<String, u64>>(&t1, &DecodingKey::from_secret(b"k"), &Validation::new(alg));
    // 4: the crypto module directly
    let s = jsonwebtoken::crypto::sign(b"msg", &EncodingKey::from_secret(b"k"), Algorithm::HS256).unwrap();
    let _ = jsonwebtoken::crypto::verify(&s, b"msg", &DecodingKey::from_secret(b"k"), Algorithm::HS256);
    // 5: an RSA key with an HMAC algorithm: jsonwebtoken refuses it
    let rsa = DecodingKey::from_rsa_pem(include_bytes!("../Cargo.toml")).unwrap();
    let _ = decode::<BTreeMap<String, u64>>(&t1, &rsa, &Validation::new(Algorithm::HS256));
}
