// audit 13 probe jl1: Validation lists written by container calls not modelled, helpers, alternatives
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use std::collections::HashMap;
type C = HashMap<String, String>;
const PEM: &[u8] = b"-----BEGIN PLACEHOLDER-----\nnot a key\n-----END PLACEHOLDER-----\n";
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn base() -> Validation { Validation::new(Algorithm::RS256) }
fn build() -> Vec<Algorithm> { let mut l = vec![Algorithm::RS256]; l.push(Algorithm::HS384); l }
fn mk(a: Algorithm) -> Vec<Algorithm> { vec![a] }
fn hs() -> Algorithm { Algorithm::HS256 }
fn dec(t: &str, dk: &DecodingKey, alg: Algorithm) { let v = Validation::new(alg); let _ = decode::<C>(t, dk, &v); }
struct Conf { a: Algorithm }

fn main() {
    let t = arg(1);
    let dk = DecodingKey::from_rsa_pem(PEM).unwrap();
    let mut v1 = base();
    v1.algorithms.insert(0, Algorithm::HS256);
    let _ = decode::<C>(&t, &dk, &v1);
    let mut v2 = base();
    v2.algorithms.extend_from_slice(&[Algorithm::HS256]);
    let _ = decode::<C>(&t, &dk, &v2);
    let mut v3 = base();
    v3.algorithms.append(&mut vec![Algorithm::HS256]);
    let _ = decode::<C>(&t, &dk, &v3);
    let mut v4 = base();
    v4.algorithms.resize(2, Algorithm::HS256);
    let _ = decode::<C>(&t, &dk, &v4);
    let mut v5 = base();
    v5.algorithms = [Algorithm::RS256, Algorithm::HS256].to_vec();
    let _ = decode::<C>(&t, &dk, &v5);
    let mut v6 = base();
    v6.algorithms = [Algorithm::RS256, Algorithm::HS256].iter().copied().collect();
    let _ = decode::<C>(&t, &dk, &v6);
    let mut v7 = base();
    v7.algorithms.extend(std::iter::repeat(Algorithm::HS512).take(1));
    let _ = decode::<C>(&t, &dk, &v7);
    let mut v8 = base();
    let mut other = Vec::new();
    other.push(Algorithm::RS256);
    other.push(Algorithm::HS256);
    v8.algorithms = other.clone();
    let _ = decode::<C>(&t, &dk, &v8);
    let mut v9 = base();
    v9.algorithms = build();
    let _ = decode::<C>(&t, &dk, &v9);
    let mut v10 = base();
    v10.algorithms = vec![Algorithm::RS256, Algorithm::RS384];
    let _ = decode::<C>(&t, &dk, &v10);
    let c = Conf { a: Algorithm::RS512 };
    let mut v11 = base();
    v11.algorithms.push(c.a);
    let _ = decode::<C>(&t, &dk, &v11);
    dec(&t, &dk, Algorithm::RS256);
    dec(&t, &dk, Algorithm::HS256);
    let mut v12 = base();
    v12.algorithms = if arg(3).is_empty() { mk(Algorithm::RS384) } else { mk(Algorithm::HS256) };
    let _ = decode::<C>(&t, &dk, &v12);
    let mut v13 = base();
    v13.algorithms = if arg(4).is_empty() { vec![Algorithm::RS384] } else { vec![hs()] };
    let _ = decode::<C>(&t, &dk, &v13);
    let mut v14 = base();
    v14.algorithms = if arg(5).is_empty() { vec![Algorithm::RS384] } else { vec![Algorithm::HS256] };
    let _ = decode::<C>(&t, &dk, &v14);
    let other_conf = Conf { a: Algorithm::HS384 };
    let _ = other_conf.a;
}
