// jsonwebtoken 9 (fourth audit round): a signing key decoded from PEM is private key material
// of its family, with its provenance (hard-coded here); the HMAC secret as before
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};

const PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIBj0r0kQ9b9Yb1JtCyhb0v3q+xg2m7S7S7n0b2j1lQ8T\n-----END PRIVATE KEY-----\n";

fn main() {
    let claims = std::collections::BTreeMap::from([("sub", "x")]);
    let k1 = EncodingKey::from_ed_pem(PEM).unwrap();
    let _ = encode(&Header::new(Algorithm::EdDSA), &claims, &k1);
    let k2 = EncodingKey::from_secret(b"jwt-secret");
    let _ = encode(&Header::default(), &claims, &k2);
    let d = DecodingKey::from_secret(std::env::var("S").unwrap().as_bytes());
    let _ = decode::<std::collections::BTreeMap<String, String>>(
        "t",
        &d,
        &Validation::new(Algorithm::HS512),
    );
}
