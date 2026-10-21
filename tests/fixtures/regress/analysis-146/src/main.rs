// audit 13 probe sl1: selector: configuration exactly when input chooses
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use std::collections::HashMap;
type C = HashMap<String, String>;
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn alg_for(i: u8) -> Algorithm { match i { 0 => Algorithm::HS256, _ => Algorithm::HS384 } }
fn outer(i: u8) -> Algorithm { alg_for(i) }
fn two_writes() -> Header { let mut h = Header::new(Algorithm::HS256); h.alg = Algorithm::HS512; h }
struct Cfg { fast: bool }
impl Cfg { fn alg(&self) -> Algorithm { if self.fast { Algorithm::HS256 } else { Algorithm::HS384 } } }
fn rec(c: &C, k: &EncodingKey, n: u8) { if n < 2 { let _ = encode(&Header::new(alg_for(n)), c, k); rec(c, k, n + 1); } }
fn by_flag(f: bool) -> Algorithm { if f { Algorithm::HS256 } else { Algorithm::HS384 } }

fn main() {
    let c = C::new();
    let k = EncodingKey::from_secret(b"placeholder");
    let _ = encode(&Header::new(outer(1)), &c, &k);
    let _ = encode(&Header::new(outer(arg(1).len() as u8)), &c, &k);
    if let Some(x) = arg(2).bytes().next() { let _ = encode(&Header::new(alg_for(x.wrapping_sub(b'a'))), &c, &k); }
    let _ = encode(&Header::new(alg_for(arg(3).parse().unwrap_or(0))), &c, &k);
    for (i, _) in ["a", "b"].iter().enumerate() { let _ = encode(&Header::new(alg_for(i as u8)), &c, &k); }
    let mut j = 0u8;
    while j < 2 { let _ = encode(&Header::new(alg_for(j)), &c, &k); j += 1; }
    let _ = encode(&two_writes(), &c, &k);
    let cfg = Cfg { fast: true };
    let _ = encode(&Header::new(cfg.alg()), &c, &k);
    rec(&c, &k, 0);
    let _ = encode(&Header::new(by_flag(arg(4).is_empty())), &c, &k);
    let _ = encode(&Header::new(by_flag(true)), &c, &k);
}
