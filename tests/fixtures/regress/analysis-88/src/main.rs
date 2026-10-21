// round 12 regress (audit 11 probe jw3): Validation lists of one family written in other ways (must be followed or unknown, never wrong)
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use std::collections::HashMap;

type C = HashMap<String, String>;
const PEM: &[u8] = b"-----BEGIN PLACEHOLDER-----\nnot a key\n-----END PLACEHOLDER-----\n";
const RSA_ALGS: &[Algorithm] = &[Algorithm::RS384, Algorithm::RS512];
const RSA_ARR: [Algorithm; 2] = [Algorithm::PS256, Algorithm::PS384];
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn rsa_list() -> Vec<Algorithm> { vec![Algorithm::RS384, Algorithm::RS512] }

fn main() {
    let t = arg(1);
    let dk = DecodingKey::from_rsa_pem(PEM).unwrap();
    let mut v1 = Validation::new(Algorithm::RS256);
    v1.algorithms.extend_from_slice(&[Algorithm::RS384, Algorithm::RS512]);
    let _ = decode::<C>(&t, &dk, &v1);
    let mut v2 = Validation::new(Algorithm::RS256);
    v2.algorithms = RSA_ALGS.to_vec();
    let _ = decode::<C>(&t, &dk, &v2);
    let mut v3 = Validation::new(Algorithm::RS256);
    v3.algorithms.extend(RSA_ARR);
    let _ = decode::<C>(&t, &dk, &v3);
    let mut v4 = Validation::new(Algorithm::RS256);
    v4.algorithms = rsa_list();
    let _ = decode::<C>(&t, &dk, &v4);
    let mut v5 = Validation::new(Algorithm::RS256);
    v5.algorithms[0] = Algorithm::RS512;
    let _ = decode::<C>(&t, &dk, &v5);
    let mut v6 = Validation::new(Algorithm::RS256);
    v6.algorithms.push(Algorithm::HS256);
    v6.algorithms.retain(|a| *a != Algorithm::HS256);
    let _ = decode::<C>(&t, &dk, &v6);
    let mut v7 = Validation::new(Algorithm::RS256);
    v7.algorithms.clear();
    v7.algorithms.push(Algorithm::PS512);
    let _ = decode::<C>(&t, &dk, &v7);
}
