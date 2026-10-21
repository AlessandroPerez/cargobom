// audit 8 probe j4: a header from a program function returning Option<Header> / Result<Header>
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use std::collections::BTreeMap;

fn hdr2(b: bool) -> Option<Header> {
    if b {
        Some(Header::new(Algorithm::RS256))
    } else {
        Some(Header { alg: Algorithm::RS512, ..Default::default() })
    }
}

fn hdr3(b: bool) -> Result<Header, String> {
    if b {
        return Ok(Header::new(Algorithm::PS256));
    }
    let mut h = Header::default();
    h.alg = Algorithm::PS384;
    Ok(h)
}

fn main() {
    let claims = BTreeMap::from([("exp", 4_000_000_000u64)]);
    let rsa = EncodingKey::from_rsa_pem(include_bytes!("rsa.pem")).unwrap();
    let c = std::env::args().count() > 1;
    let _ = encode(&hdr2(c).unwrap(), &claims, &rsa); // RSA-PKCS1-1.5-SHA-256, RSA-PKCS1-1.5-SHA-512
    let _ = encode(&hdr3(c).unwrap(), &claims, &rsa); // RSA-PSS-SHA-256, RSA-PSS-SHA-384
}
