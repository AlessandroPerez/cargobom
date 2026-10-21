// round 12 regress (audit 11 probe jw1): Validation lists written in other ways, selector with constant-looking arguments
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use std::collections::HashMap;
use std::sync::Mutex;

type C = HashMap<String, String>;
const PEM: &[u8] = b"-----BEGIN PLACEHOLDER-----\nnot a key\n-----END PLACEHOLDER-----\n";
const ALGS: &[Algorithm] = &[Algorithm::RS256, Algorithm::HS256];
static MODE: Mutex<u8> = Mutex::new(0);
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn algs() -> Vec<Algorithm> { vec![Algorithm::RS256, Algorithm::HS256] }
fn mk(v: &mut Vec<Algorithm>) { v.push(Algorithm::HS256); }
fn alg_env(_default: u8) -> Algorithm { if std::env::args().count() > 2 { Algorithm::HS512 } else { Algorithm::HS256 } }
fn alg_mode(m: &Mutex<u8>) -> Algorithm { if *m.lock().unwrap() == 0 { Algorithm::HS256 } else { Algorithm::HS384 } }
fn alg_for(i: u8) -> Algorithm { match i { 0 => Algorithm::HS256, _ => Algorithm::HS384 } }

fn main() {
    let c = C::new();
    let t = arg(1);
    let dk = DecodingKey::from_rsa_pem(PEM).unwrap();
    let mut v1 = Validation::new(Algorithm::RS256);
    v1.algorithms.insert(0, Algorithm::HS256);
    let _ = decode::<C>(&t, &dk, &v1);
    let mut v2 = Validation::new(Algorithm::RS256);
    v2.algorithms[0] = Algorithm::HS256;
    let _ = decode::<C>(&t, &dk, &v2);
    let mut v3 = Validation::new(Algorithm::RS256);
    *v3.algorithms.first_mut().unwrap() = Algorithm::HS256;
    let _ = decode::<C>(&t, &dk, &v3);
    let mut v4 = Validation::new(Algorithm::RS256);
    v4.algorithms.iter_mut().for_each(|a| *a = Algorithm::HS256);
    let _ = decode::<C>(&t, &dk, &v4);
    let mut v5 = Validation::new(Algorithm::RS256);
    v5.algorithms = algs();
    let _ = decode::<C>(&t, &dk, &v5);
    let mut v6 = Validation::new(Algorithm::RS256);
    v6.algorithms = ALGS.to_vec();
    let _ = decode::<C>(&t, &dk, &v6);
    let mut v7 = Validation::new(Algorithm::RS256);
    v7.algorithms = [Algorithm::RS256, Algorithm::HS256].into_iter().collect();
    let _ = decode::<C>(&t, &dk, &v7);
    let mut v8 = Validation::new(Algorithm::RS256);
    v8.algorithms.append(&mut vec![Algorithm::HS256]);
    let _ = decode::<C>(&t, &dk, &v8);
    let mut v9 = Validation::new(Algorithm::RS256);
    v9.algorithms.resize(2, Algorithm::HS256);
    let _ = decode::<C>(&t, &dk, &v9);
    let mut v10 = Validation::new(Algorithm::RS256);
    mk(&mut v10.algorithms);
    let _ = decode::<C>(&t, &dk, &v10);
    let mut v11 = Validation::default();
    v11.algorithms.push(Algorithm::RS256);
    let _ = decode::<C>(&t, &dk, &v11);
    let v12 = Validation::default();
    let _ = decode::<C>(&t, &dk, &v12);
    let mut v13 = Validation::new(Algorithm::RS256);
    let other = vec![Algorithm::HS256];
    v13.algorithms.clone_from(&other);
    let _ = decode::<C>(&t, &dk, &v13);
    let mut v14 = Validation::new(Algorithm::RS256);
    let w = Validation::new(Algorithm::HS384);
    v14.algorithms.extend(w.algorithms.iter().copied());
    let _ = decode::<C>(&t, &dk, &v14);
    let hk = DecodingKey::from_secret(b"placeholder");
    let mut v15 = Validation::new(Algorithm::HS256);
    v15.algorithms.push(Algorithm::RS256);
    let _ = decode::<C>(&t, &hk, &v15);
    let k = EncodingKey::from_secret(b"placeholder");
    *MODE.lock().unwrap() = arg(2).len() as u8;
    let _ = encode(&Header::new(alg_env(0)), &c, &k);
    let _ = encode(&Header::new(alg_mode(&MODE)), &c, &k);
    for i in [0u8, 1] { let _ = encode(&Header::new(alg_for(i)), &c, &k); }
    let _ = encode(&Header::new(alg_for(arg(3).len() as u8)), &c, &k);
}
