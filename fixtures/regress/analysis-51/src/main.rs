// audit 9 probe j5: jsonwebtoken key families from every constructor; headers through Option /
// Result / `?`; const and static algorithms (placeholder key text: analysed, never run)
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use std::collections::HashMap;
use std::str::FromStr;

type C = HashMap<String, String>;
const PEM: &[u8] = b"-----BEGIN PLACEHOLDER-----\nnot a key\n-----END PLACEHOLDER-----\n";
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn parsed() -> Algorithm { Algorithm::from_str(&arg(1)).unwrap() }

static SA: Algorithm = Algorithm::PS512;
struct Cfg { alg: Algorithm }
static CFG: Cfg = Cfg { alg: Algorithm::HS384 };
const ALGS: [Algorithm; 2] = [Algorithm::RS256, Algorithm::RS384];
static VALGS: &[Algorithm] = &[Algorithm::ES256, Algorithm::ES384];

fn hdr(b: bool) -> Option<Header> { if b { Some(Header::new(Algorithm::HS384)) } else { None } }
fn hdr2() -> Result<Header, std::num::ParseIntError> {
    let n: u8 = arg(2).parse()?;
    let mut h = Header::default();
    if n > 2 { h.alg = Algorithm::HS512; }
    Ok(h)
}
fn key(b: bool) -> Result<EncodingKey, jsonwebtoken::errors::Error> {
    if b { Ok(EncodingKey::from_secret(b"k")) } else { EncodingKey::from_rsa_pem(PEM) }
}
fn enc2(c: &C) -> Result<String, Box<dyn std::error::Error>> {
    let h = hdr2()?;
    Ok(encode(&h, c, &EncodingKey::from_secret(b"k"))?) // HS256, HS512
}

fn main() {
    let c = C::new();
    let t = arg(3);
    let _ = encode(&Header::new(parsed()), &c, &EncodingKey::from_secret(b"k")); // HS*
    let _ = encode(&Header::new(parsed()), &c, &EncodingKey::from_base64_secret("aGk=").unwrap()); // HS*
    let _ = encode(&Header::new(parsed()), &c, &EncodingKey::from_rsa_pem(PEM).unwrap()); // RS*, PS*
    let _ = encode(&Header::new(parsed()), &c, &EncodingKey::from_rsa_der(PEM)); // RS*, PS*
    let _ = encode(&Header::new(parsed()), &c, &EncodingKey::from_ec_pem(PEM).unwrap()); // ES*
    let _ = encode(&Header::new(parsed()), &c, &EncodingKey::from_ec_der(PEM)); // ES*
    let _ = encode(&Header::new(parsed()), &c, &EncodingKey::from_ed_pem(PEM).unwrap()); // EdDSA
    let _ = encode(&Header::new(parsed()), &c, &EncodingKey::from_ed_der(PEM)); // EdDSA
    let _ = encode(&Header::new(parsed()), &c, &key(arg(4).is_empty()).unwrap()); // HS*, RS*, PS*
    let v = Validation::new(parsed());
    let _ = decode::<C>(&t, &DecodingKey::from_secret(b"k"), &v); // HS*
    let _ = decode::<C>(&t, &DecodingKey::from_base64_secret("aGk=").unwrap(), &v); // HS*
    let _ = decode::<C>(&t, &DecodingKey::from_rsa_pem(PEM).unwrap(), &v); // RS*, PS*
    let _ = decode::<C>(&t, &DecodingKey::from_rsa_components("n", "e").unwrap(), &v); // RS*, PS*
    let _ = decode::<C>(&t, &DecodingKey::from_rsa_raw_components(b"n", b"e"), &v); // RS*, PS*
    let _ = decode::<C>(&t, &DecodingKey::from_rsa_der(PEM), &v); // RS*, PS*
    let _ = decode::<C>(&t, &DecodingKey::from_ec_pem(PEM).unwrap(), &v); // ES*
    let _ = decode::<C>(&t, &DecodingKey::from_ec_components("x", "y").unwrap(), &v); // ES*
    let _ = decode::<C>(&t, &DecodingKey::from_ec_der(PEM), &v); // ES*
    let _ = decode::<C>(&t, &DecodingKey::from_ed_pem(PEM).unwrap(), &v); // EdDSA
    let _ = decode::<C>(&t, &DecodingKey::from_ed_components("x").unwrap(), &v); // EdDSA
    let _ = decode::<C>(&t, &DecodingKey::from_ed_der(PEM), &v); // EdDSA
    let jwk: Jwk = serde_json::from_str(&arg(5)).unwrap();
    let _ = decode::<C>(&t, &DecodingKey::from_jwk(&jwk).unwrap(), &v); // all 12
    let _ = encode(&hdr(arg(6).is_empty()).unwrap_or_default(), &c, &EncodingKey::from_secret(b"k")); // HS256, HS384
    let _ = enc2(&c);
    let _ = encode(&Header::new(SA), &c, &EncodingKey::from_rsa_pem(PEM).unwrap()); // PS512
    let _ = encode(&Header { alg: SA, ..Default::default() }, &c, &EncodingKey::from_rsa_der(PEM)); // PS512
    let _ = encode(&Header::new(CFG.alg), &c, &EncodingKey::from_secret(b"k")); // HS384
    let mut v2 = Validation::new(Algorithm::RS256);
    v2.algorithms = ALGS.to_vec();
    let _ = decode::<C>(&t, &DecodingKey::from_rsa_pem(PEM).unwrap(), &v2); // RS256, RS384
    let mut v3 = Validation::new(Algorithm::ES256);
    v3.algorithms = VALGS.to_vec();
    let _ = decode::<C>(&t, &DecodingKey::from_ec_pem(PEM).unwrap(), &v3); // ES256, ES384
    let _ = encode(&Header::new(Algorithm::HS256), &c, &EncodingKey::from_rsa_pem(PEM).unwrap()); // refused: none
}
