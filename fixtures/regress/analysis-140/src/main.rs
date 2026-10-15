// audit 13 probe jl3: alternatives (not co-members) for encode headers and decode lists; parsed variants
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use std::collections::HashMap;
use std::str::FromStr;
type C = HashMap<String, String>;
const PEM: &[u8] = b"-----BEGIN PLACEHOLDER-----\nnot a key\n-----END PLACEHOLDER-----\n";
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn val(a: Algorithm) -> Validation { Validation::new(a) }
fn hdr(a: Algorithm) -> Header { Header::new(a) }

fn main() {
    let t = arg(1);
    let i = arg(2).len();
    let ek = EncodingKey::from_secret(b"k");
    let algs = [Algorithm::HS256, Algorithm::RS256];
    let _ = encode(&Header::new(algs[i % 2]), &1u8, &ek);
    let mut m = HashMap::new();
    m.insert("a", Algorithm::HS384);
    m.insert("b", Algorithm::ES384);
    let _ = encode(&Header::new(*m.get(t.as_str()).unwrap()), &1u8, &ek);
    let h = if i > 3 { hdr(Algorithm::HS512) } else { hdr(Algorithm::PS256) };
    let _ = encode(&h, &1u8, &ek);
    let dk = DecodingKey::from_rsa_pem(PEM).unwrap();
    let v1 = if i > 3 { val(Algorithm::RS256) } else { val(Algorithm::HS256) };
    let _ = decode::<C>(&t, &dk, &v1);
    let v2 = if i > 4 { Validation::new(Algorithm::PS384) } else { Validation::new(Algorithm::HS384) };
    let _ = decode::<C>(&t, &dk, &v2);
    let mut v3 = Validation::new(Algorithm::RS256);
    v3.algorithms.push(Algorithm::from_str(&arg(3)).unwrap());
    let _ = decode::<C>(&t, &dk, &v3);
    let v4 = Validation::new(Algorithm::from_str(&arg(4)).unwrap());
    let _ = decode::<C>(&t, &dk, &v4);
}
