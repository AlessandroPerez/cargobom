// audit 9 probe j6: set labels: which members are chosen by input (selector: configuration) and
// which are fixed by the program (callers, constant branches, loops over all, type-join)
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use std::collections::HashMap;

type C = HashMap<String, String>;
const FLAG: bool = true;
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn sign_with(alg: Algorithm, c: &C) -> String { encode(&Header::new(alg), c, &EncodingKey::from_secret(b"k")).unwrap() } // HS256, HS384: each caller's
struct Svc { h: Header }
fn mk_svc(alg: Algorithm) -> Svc { Svc { h: Header::new(alg) } }
fn dead_svc() -> Svc { mk_svc(Algorithm::HS512) }

fn main() {
    let c = C::new();
    let t1 = sign_with(Algorithm::HS256, &c);
    let t2 = sign_with(Algorithm::HS384, &c);
    let a = if FLAG { Algorithm::HS256 } else { Algorithm::HS512 };
    let _ = encode(&Header::new(a), &c, &EncodingKey::from_secret(b"k")); // HS256: constant branch
    for alg in [Algorithm::HS256, Algorithm::HS384] {
        let _ = encode(&Header::new(alg), &c, &EncodingKey::from_secret(b"k")); // HS256, HS384: both, every run
    }
    let s = mk_svc(Algorithm::HS384);
    let _ = encode(&s.h, &c, &EncodingKey::from_secret(b"k")); // HS384 (mk_svc's HS512 caller is dead)
    let v = Validation::new(if arg(1).is_empty() { Algorithm::HS256 } else { Algorithm::HS512 });
    let _ = decode::<C>(&t1, &DecodingKey::from_secret(b"k"), &v); // HS256, HS512: input selects
    let _ = decode::<C>(&t2, &DecodingKey::from_secret(b"k"), &Validation::new(Algorithm::HS384)); // HS384
}
