// audit 8 probe j2: headers and validations built in program functions, JWK keys
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use std::collections::BTreeMap;

type C = BTreeMap<String, u64>;
fn claims() -> C { C::from([("exp".to_string(), 4_000_000_000u64)]) }
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

fn hdr(b: bool) -> Header {
    if b {
        Header::new(Algorithm::RS256)
    } else {
        Header { alg: Algorithm::RS512, ..Default::default() }
    }
}

fn val(b: bool) -> Validation {
    let mut v = Validation::new(Algorithm::ES256);
    if b {
        v.algorithms = vec![Algorithm::ES384];
    }
    v
}

fn main() {
    let rsa = EncodingKey::from_rsa_pem(include_bytes!("rsa.pem")).unwrap();
    let t = encode(&hdr(arg(1).is_empty()), &claims(), &rsa).unwrap(); // RSA-PKCS1-1.5-SHA-256, RSA-PKCS1-1.5-SHA-512
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_str(&arg(2)).unwrap();
    let key = DecodingKey::from_jwk(&jwk).unwrap();
    let _ = decode::<C>(&t, &key, &val(arg(3).is_empty())); // ECDSA-P-256-SHA-256, ECDSA-P-384-SHA-384
    let _ = decode::<C>(&t, &key, &Validation::new(Algorithm::RS256)); // RSA-PKCS1-1.5-SHA-256
    let _ = decode::<C>(&t, &key, &Validation::new(Algorithm::HS256)); // HMAC-SHA-256
    let h = Header { kid: Some(arg(4)), alg: Algorithm::ES256, ..Default::default() };
    let ec = EncodingKey::from_ec_pem(include_bytes!("ec256.pem")).unwrap();
    let _ = encode(&h, &claims(), &ec); // ECDSA-P-256-SHA-256
}
