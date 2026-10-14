// audit 9 probe j7: type-join members of the boundary model and dead stores
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use std::collections::HashMap;

type C = HashMap<String, String>;
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
struct Svc { h: Header }
#[allow(dead_code)]
fn dead_svc() -> Svc { let mut h = Header::default(); h.alg = Algorithm::HS512; Svc { h } }
#[allow(dead_code)]
static DEAD: Svc = Svc { h: Header { typ: None, alg: Algorithm::HS384, cty: None, jku: None, jwk: None, kid: None, x5u: None, x5c: None, x5t: None, x5t_s256: None } };

fn main() {
    let c = C::new();
    let mut m: HashMap<String, Svc> = HashMap::new();
    m.insert(arg(1), Svc { h: Header::new(Algorithm::HS256) });
    let s = &m[&arg(2)];
    let _ = encode(&s.h, &c, &EncodingKey::from_secret(b"k")); // HS256 (the only Svc in the map)
    let b: Box<dyn std::any::Any> = Box::new(Svc { h: Header::new(Algorithm::HS256) });
    let s2 = b.downcast_ref::<Svc>().unwrap();
    let _ = encode(&s2.h, &c, &EncodingKey::from_secret(b"k")); // HS256
}
