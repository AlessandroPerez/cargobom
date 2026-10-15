// audit 13 probe jl5: a decode whose list is one of two alternatives (one refused): the other is used
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use std::collections::HashMap;
type C = HashMap<String, String>;
const PEM: &[u8] = b"-----BEGIN PLACEHOLDER-----\nnot a key\n-----END PLACEHOLDER-----\n";
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn check(t: &str, alg: Algorithm) -> bool {
    let dk = DecodingKey::from_rsa_pem(PEM).unwrap();
    decode::<C>(t, &dk, &Validation::new(alg)).is_ok()
}

fn main() {
    let t = arg(1);
    let legacy = arg(2) == "legacy";
    let ok = if legacy { check(&t, Algorithm::HS256) } else { check(&t, Algorithm::RS256) };
    println!("{ok}");
}
