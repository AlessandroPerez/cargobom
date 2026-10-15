// audit 12 probe sel1: selector: configuration when constants are chosen by input
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use std::collections::HashMap;
type C = HashMap<String, String>;
const IDX: u8 = 1;
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn alg_for(i: u8) -> Algorithm { match i { 0 => Algorithm::HS256, _ => Algorithm::HS384 } }

fn main() {
    let c = C::new();
    let k = EncodingKey::from_secret(b"placeholder");
    let sel = if arg(1).is_empty() { 0 } else { 1 };
    let _ = encode(&Header::new(alg_for(sel)), &c, &k);
    let _ = encode(&Header::new(alg_for(match arg(2).as_str() { "a" => 0, _ => 1 })), &c, &k);
    for n in std::env::args().map(|a| a.len() as u8) { let _ = encode(&Header::new(alg_for(n)), &c, &k); }
    for i in 0..2u8 { let _ = encode(&Header::new(alg_for(i)), &c, &k); }
    let _ = encode(&Header::new(alg_for(IDX)), &c, &k);
    let h = if arg(3).is_empty() { Header::new(alg_for(0)) } else { Header::new(alg_for(1)) };
    let _ = encode(&h, &c, &k);
}
