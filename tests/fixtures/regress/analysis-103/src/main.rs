// audit 12 probe sel2: selector when a loop-carried or input-dependent counter picks the algorithm
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use std::collections::HashMap;
type C = HashMap<String, String>;
fn alg_for(i: u8) -> Algorithm { match i { 0 => Algorithm::HS256, _ => Algorithm::HS384 } }

fn main() {
    let c = C::new();
    let k = EncodingKey::from_secret(b"placeholder");
    let mut n = 0u8;
    for _ in std::env::args() { n = n.wrapping_add(1); }
    let _ = encode(&Header::new(alg_for(n)), &c, &k);
    let mut m = 0u8;
    for a in std::env::args() { if a.len() > 3 { m = 1; } }
    let _ = encode(&Header::new(alg_for(m)), &c, &k);
}
