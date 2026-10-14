// audit 8 probe j1: jsonwebtoken boundary model variations (expected `must` in comments)
use jsonwebtoken::{crypto, decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use std::collections::BTreeMap;
use std::str::FromStr;

type C = BTreeMap<String, u64>;
fn claims() -> C { C::from([("exp".to_string(), 4_000_000_000u64)]) }
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn hs() -> EncodingKey { EncodingKey::from_secret(b"k") }
fn hsd() -> DecodingKey { DecodingKey::from_secret(b"k") }
fn rsa() -> EncodingKey { EncodingKey::from_rsa_pem(include_bytes!("rsa.pem")).unwrap() }
fn rsad() -> DecodingKey { DecodingKey::from_rsa_pem(include_bytes!("rsa_pub.pem")).unwrap() }

struct Cfg { alg: Algorithm }
const ALG: Algorithm = Algorithm::ES384;
fn pick() -> Algorithm { Algorithm::RS384 }
fn maybe(a: &mut Algorithm, b: bool) { if b { *a = Algorithm::HS512; } }
fn set_hdr(h: &mut Header, b: bool) { if b { h.alg = Algorithm::HS512; } }
struct W { h: Header }
impl W { fn upgrade(&mut self) { self.h.alg = Algorithm::HS384; } }
fn make_header() -> Header { let mut h = Header::default(); h.alg = Algorithm::HS512; h }
fn verify_with(alg: Algorithm, t: &str) -> bool { decode::<C>(t, &hsd(), &Validation::new(alg)).is_ok() }

fn main() {
    let cfg = Cfg { alg: Algorithm::HS512 };
    let t = encode(&Header::new(cfg.alg), &claims(), &hs()).unwrap(); // field: HMAC-SHA-512
    let _ = encode(&Header::new(pick()), &claims(), &rsa()); // fn return: RSA-PKCS1-1.5-SHA-384
    let a3 = match arg(1).as_str() { "a" => Algorithm::HS256, "b" => Algorithm::HS384, _ => Algorithm::HS512 };
    let _ = encode(&Header::new(a3), &claims(), &hs()); // match: HMAC-SHA-256/384/512
    let ec = EncodingKey::from_ec_pem(include_bytes!("ec384.pem")).unwrap();
    let _ = encode(&Header::new(ALG), &claims(), &ec); // const: ECDSA-P-384-SHA-384
    let a5 = Algorithm::from_str(&arg(2)).unwrap();
    let _ = encode(&Header::new(a5), &claims(), &hs()); // from_str + HMAC key: HMAC-SHA-256/384/512 only
    let h6 = Header { alg: Algorithm::HS384, ..Default::default() };
    let _ = encode(&h6, &claims(), &hs()); // struct literal: HMAC-SHA-384
    let mut v7 = Validation::new(Algorithm::HS256);
    v7.algorithms.push(Algorithm::HS512);
    let _ = decode::<C>(&t, &hsd(), &v7); // push: HMAC-SHA-256, HMAC-SHA-512
    let mut v8 = Validation::new(Algorithm::HS384);
    v8.set_audience(&["x"]);
    let _ = decode::<C>(&t, &hsd(), &v8); // set_audience: HMAC-SHA-384
    let mut v9 = Validation::new(Algorithm::RS256);
    v9.algorithms.push(Algorithm::HS256);
    let _ = decode::<C>(&t, &rsad(), &v9); // RS256 and HS256 with an RSA key: jsonwebtoken refuses the call; reported RS256 (the family check is per algorithm: stated limitation)
    let _ = encode(&Header::new(Algorithm::HS256), &claims(), &rsa()); // HMAC alg with an RSA key: encode refuses: nothing
    let _ = decode::<C>(&t, &hsd(), &Validation::default()); // default: HMAC-SHA-256
    let _ = verify_with(Algorithm::HS256, &t) && verify_with(Algorithm::HS384, &t); // decode at L21: HMAC-SHA-256/384
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_str(&arg(3)).unwrap();
    let _ = decode::<C>(&t, &DecodingKey::from_jwk(&jwk).unwrap(), &Validation::new(Algorithm::ES256)); // jwk: ECDSA-P-256-SHA-256
    let mut v11 = Validation::new(Algorithm::ES256);
    v11.algorithms = vec![Algorithm::ES256, Algorithm::ES384];
    let _ = decode::<C>(&t, &DecodingKey::from_ec_der(b"der"), &v11); // EC der: ECDSA-P-256-SHA-256, ECDSA-P-384-SHA-384
    let _ = decode::<C>(&t, &DecodingKey::from_ed_der(b"der"), &Validation::new(Algorithm::EdDSA)); // Ed25519
    let _ = decode::<C>(&t, &DecodingKey::from_base64_secret("a2V5").unwrap(), &Validation::new(Algorithm::HS512)); // HMAC-SHA-512
    let tok = arg(4);
    let rc = DecodingKey::from_rsa_components("AQAB", "AQAB").unwrap();
    let _ = decode::<C>(&tok, &rc, &Validation::new(decode_header(&tok).unwrap().alg)); // token alg, RSA key: RS*/PS* (6)
    let a17 = if arg(5).is_empty() { Algorithm::HS256 } else { Algorithm::HS384 };
    let _ = crypto::sign(b"m", &hs(), a17); // crypto::sign: HMAC-SHA-256/384
    let _ = encode(&make_header(), &claims(), &hs()); // header from a fn with a field write: HMAC-SHA-512
    let mut h20 = Header::new(Algorithm::HS256);
    if arg(6) == "x" { h20.alg = Algorithm::HS384; }
    let _ = encode(&h20, &claims(), &hs()); // conditional write: HMAC-SHA-256, HMAC-SHA-384
    let mut h21 = Header::new(Algorithm::HS256);
    for _ in 0..arg(7).len() { h21.alg = Algorithm::HS512; }
    let _ = encode(&h21, &claims(), &hs()); // write in a loop: HMAC-SHA-256, HMAC-SHA-512
    let _ = early(); // see below
    let mut h23 = Header::new(Algorithm::HS256);
    h23.alg = Algorithm::HS384;
    h23 = Header::new(Algorithm::HS512);
    let _ = encode(&h23, &claims(), &hs()); // write then reassigned: HMAC-SHA-512
    let mut h24 = Header::new(Algorithm::HS256);
    let r = &mut h24;
    r.alg = Algorithm::HS384;
    let _ = encode(&h24, &claims(), &hs()); // write through a reference: HMAC-SHA-384
    let mut h25 = Header::new(Algorithm::HS256);
    maybe(&mut h25.alg, arg(8) == "x");
    let _ = encode(&h25, &claims(), &hs()); // conditional write by a program fn: HMAC-SHA-256, HMAC-SHA-512
    let mut w = W { h: Header::new(Algorithm::HS256) };
    w.upgrade();
    let _ = encode(&w.h, &claims(), &hs()); // method writes a field of *self: HMAC-SHA-384
    let mut h27 = Header::new(Algorithm::HS256);
    set_hdr(&mut h27, arg(9) == "x");
    let _ = encode(&h27, &claims(), &hs()); // fn writes field through &mut Header conditionally: HMAC-SHA-256, HMAC-SHA-512
    let a28 = if arg(10).is_empty() { Some(Algorithm::HS384) } else { None }.unwrap_or(Algorithm::HS256);
    let _ = encode(&Header::new(a28), &claims(), &hs()); // Option fallback: HMAC-SHA-256, HMAC-SHA-384
}

fn early() -> String {
    let mut h = Header::new(Algorithm::HS256);
    if arg(11).is_empty() {
        return encode(&h, &claims(), &hs()).unwrap(); // early return: HMAC-SHA-256
    }
    h.alg = Algorithm::HS384;
    encode(&h, &claims(), &hs()).unwrap() // after the write: HMAC-SHA-384
}
