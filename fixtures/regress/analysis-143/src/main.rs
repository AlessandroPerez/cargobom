// audit 13 probe jl6: lists read where the object is not followed (type-join), with another object's list pushed with HMAC variants
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use std::collections::HashMap;
type C = HashMap<String, String>;
const PEM: &[u8] = b"-----BEGIN PLACEHOLDER-----\nnot a key\n-----END PLACEHOLDER-----\n";
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
struct Svc { v: Validation }

fn main() {
    let t = arg(1);
    let sk = DecodingKey::from_secret(b"k");
    let mut w = Validation::default();
    w.algorithms.push(Algorithm::HS384);
    let _ = decode::<C>(&t, &sk, &w);
    let dk = DecodingKey::from_rsa_pem(PEM).unwrap();
    let svcs = vec![Svc { v: Validation::new(Algorithm::RS256) }, Svc { v: Validation::new(Algorithm::RS512) }];
    let s = &svcs[arg(2).len() % 2];
    let _ = decode::<C>(&t, &dk, &s.v);
    let mut m: HashMap<String, Validation> = HashMap::new();
    m.insert("a".into(), Validation::new(Algorithm::PS256));
    let _ = decode::<C>(&t, &dk, &m["a"]);
    let boxed: Box<dyn Fn() -> Validation> = Box::new(|| Validation::new(Algorithm::PS512));
    let _ = decode::<C>(&t, &dk, &boxed());
}
