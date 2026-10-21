// audit 12 probe j1: Validation lists written by element, through helpers, by std moves (refused or not)
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use std::collections::HashMap;
type C = HashMap<String, String>;
const PEM: &[u8] = b"-----BEGIN PLACEHOLDER-----\nnot a key\n-----END PLACEHOLDER-----\n";
const HS_ALGS: &[Algorithm] = &[Algorithm::HS256];
static HS_S: [Algorithm; 1] = [Algorithm::HS256];
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn two() -> Validation { let mut v = Validation::new(Algorithm::RS256); v.algorithms.push(Algorithm::RS384); v }
fn mkv() -> Validation { let mut v = Validation::new(Algorithm::RS256); v.algorithms[0] = Algorithm::HS256; v }
fn tweak(v: &mut Validation) { v.algorithms[0] = Algorithm::HS256; }
struct App { v: Validation }

fn main() {
    let t = arg(1);
    let dk = DecodingKey::from_rsa_pem(PEM).unwrap();
    let mut v1 = two();
    v1.algorithms[1] = Algorithm::HS256;
    let _ = decode::<C>(&t, &dk, &v1);
    let mut v2 = two();
    if let Some(a) = v2.algorithms.get_mut(0) { *a = Algorithm::HS256; }
    let _ = decode::<C>(&t, &dk, &v2);
    let mut v3 = two();
    for a in v3.algorithms.iter_mut() { *a = Algorithm::HS384; }
    let _ = decode::<C>(&t, &dk, &v3);
    let mut v4 = two();
    v4.algorithms.fill(Algorithm::HS256);
    let _ = decode::<C>(&t, &dk, &v4);
    let mut v5 = two();
    v5.algorithms[..1].copy_from_slice(&[Algorithm::HS256]);
    let _ = decode::<C>(&t, &dk, &v5);
    let mut v6 = two();
    let _old = std::mem::replace(&mut v6.algorithms, vec![Algorithm::HS256]);
    let _ = decode::<C>(&t, &dk, &v6);
    let mut v7 = two();
    let mut other = vec![Algorithm::HS512];
    std::mem::swap(&mut v7.algorithms, &mut other);
    let _ = decode::<C>(&t, &dk, &v7);
    let mut v8 = two();
    let list = &mut v8.algorithms;
    list[0] = Algorithm::HS256;
    let _ = decode::<C>(&t, &dk, &v8);
    let mut v9 = two();
    v9.algorithms.splice(0..1, [Algorithm::HS256]);
    let _ = decode::<C>(&t, &dk, &v9);
    let mut v10 = two();
    v10.algorithms.extend(HS_ALGS);
    let _ = decode::<C>(&t, &dk, &v10);
    let mut v11 = two();
    v11.algorithms = HS_S.to_vec();
    let _ = decode::<C>(&t, &dk, &v11);
    let mut v12 = two();
    let w = Validation::new(Algorithm::HS384);
    v12.algorithms.clone_from(&w.algorithms);
    let _ = decode::<C>(&t, &dk, &v12);
    let mut app = App { v: two() };
    app.v.algorithms[0] = Algorithm::HS256;
    let _ = decode::<C>(&t, &dk, &app.v);
    let v13 = mkv();
    let _ = decode::<C>(&t, &dk, &v13);
    let mut v14 = two();
    tweak(&mut v14);
    let _ = decode::<C>(&t, &dk, &v14);
    let mut v15 = two();
    v15.algorithms[0] = Algorithm::PS256;
    let _ = decode::<C>(&t, &dk, &v15);
    let mut v16 = two();
    v16.algorithms.swap(0, 1);
    let _ = decode::<C>(&t, &dk, &v16);
    let mut v17 = two();
    *v17.algorithms.last_mut().unwrap() = Algorithm::RS512;
    let _ = decode::<C>(&t, &dk, &v17);
}
