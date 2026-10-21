// round 11 regress (audit 10 probe j1): jsonwebtoken fallbacks, dead witnesses, Validation co-members, selector, statics
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use std::collections::HashMap;

type C = HashMap<String, String>;
const PEM: &[u8] = b"-----BEGIN PLACEHOLDER-----\nnot a key\n-----END PLACEHOLDER-----\n";
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn hdr(b: bool) -> Option<Header> { if b { Some(Header::new(Algorithm::HS384)) } else { None } }
fn hres(b: bool) -> Result<Header, String> { if b { Ok(Header::new(Algorithm::HS384)) } else { Err(String::new()) } }

fn sign_with(alg: Algorithm, c: &C) { let _ = encode(&Header::new(alg), c, &EncodingKey::from_secret(b"k")); }
#[allow(dead_code)]
fn dead_caller(c: &C) { sign_with(Algorithm::HS512, c); sign_with(DEAD_ALG, c); }
#[allow(dead_code)]
static DEAD_ALG: Algorithm = Algorithm::HS384;

struct Svc { h: Header }
#[allow(dead_code)]
fn dead_store() -> Svc { Svc { h: Header::new(Algorithm::HS512) } }
fn live_store() -> Svc { Svc { h: Header::new(Algorithm::HS256) } }

fn add(v: &mut Validation) { v.algorithms.push(Algorithm::HS256); }
fn alg_for(i: u8) -> Algorithm { match i { 0 => Algorithm::HS256, _ => Algorithm::HS384 } }

struct Cfg { alg: Algorithm }
static INNER: Cfg = Cfg { alg: Algorithm::HS512 };
struct Outer { inner: &'static Cfg }
static OUTER: Outer = Outer { inner: &INNER };
static ARR: [Cfg; 2] = [Cfg { alg: Algorithm::HS256 }, Cfg { alg: Algorithm::HS384 }];

fn main() {
    let c = C::new();
    let t = arg(1);
    let k = EncodingKey::from_secret(b"k");
    let _ = encode(&hdr(arg(2).is_empty()).unwrap_or_else(|| Header::new(Algorithm::HS512)), &c, &k);
    let _ = encode(&hdr(arg(3).is_empty()).unwrap_or(Header::new(Algorithm::HS512)), &c, &k);
    let _ = encode(&hres(arg(4).is_empty()).unwrap_or_default(), &c, &k);
    let _ = encode(&Header { alg: Algorithm::HS384, ..Default::default() }, &c, &k);
    sign_with(Algorithm::HS256, &c);
    let s = live_store();
    let _ = encode(&s.h, &c, &k);
    let dk = DecodingKey::from_rsa_pem(PEM).unwrap();
    let mut v1 = Validation::new(Algorithm::RS256);
    v1.algorithms.extend([Algorithm::HS256]);
    let _ = decode::<C>(&t, &dk, &v1);
    let mut v2 = Validation::new(Algorithm::RS256);
    v2.algorithms.extend_from_slice(&[Algorithm::HS256]);
    let _ = decode::<C>(&t, &dk, &v2);
    let mut v3 = Validation::new(Algorithm::RS256);
    v3.algorithms = [Algorithm::RS256, Algorithm::HS256].to_vec();
    let _ = decode::<C>(&t, &dk, &v3);
    let mut v4 = Validation::new(Algorithm::RS256);
    add(&mut v4);
    let _ = decode::<C>(&t, &dk, &v4);
    let mut v5 = Validation::new(Algorithm::RS256);
    v5.algorithms = Vec::from([Algorithm::RS384, Algorithm::HS256]);
    let _ = decode::<C>(&t, &dk, &v5);
    let mut v6 = Validation::new(Algorithm::RS256);
    v6.algorithms = if arg(5).is_empty() { vec![Algorithm::RS384] } else { vec![Algorithm::HS256] };
    let _ = decode::<C>(&t, &dk, &v6);
    let _ = encode(&Header::new(alg_for(0)), &c, &k);
    let _ = encode(&Header::new(alg_for(1)), &c, &k);
    let _ = encode(&Header::new(OUTER.inner.alg), &c, &k);
    let i = arg(6).len() % 2;
    let _ = encode(&Header::new(ARR[i].alg), &c, &k);
    let _ = encode(&Header::new(ARR[0].alg), &c, &k);
}
