// round 12 regress (audit 11 probe jw2): values not followed reached through live closures and generic callers (not dead code)
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use std::collections::HashMap;

type C = HashMap<String, String>;
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn sign_a(alg: Algorithm, c: &C) { let _ = encode(&Header::new(alg), c, &EncodingKey::from_secret(b"k")); }
fn sign_b(alg: Algorithm, c: &C) { let _ = encode(&Header::new(alg), c, &EncodingKey::from_secret(b"k")); }
fn sign_c(alg: Algorithm, c: &C) { let _ = encode(&Header::new(alg), c, &EncodingKey::from_secret(b"k")); }
trait Src { fn alg() -> Algorithm; }
struct S;
impl Src for S { fn alg() -> Algorithm { let mut o = Some(Algorithm::HS256); if arg(3).is_empty() { if let Some(a) = o.as_mut() { *a = Algorithm::HS512; } } o.unwrap() } }
fn gen_sign<T: Src>(c: &C) { sign_c(T::alg(), c); }

fn main() {
    let c = C::new();
    let f = |c: &C| {
        let mut o = Some(Algorithm::HS256);
        if arg(1).is_empty() { if let Some(a) = o.as_mut() { *a = Algorithm::HS384; } }
        sign_a(o.unwrap(), c);
    };
    f(&c);
    let mut o = Some(Algorithm::HS256);
    if arg(2).is_empty() { if let Some(a) = o.as_mut() { *a = Algorithm::HS384; } }
    sign_b(o.unwrap(), &c);
    gen_sign::<S>(&c);
}
