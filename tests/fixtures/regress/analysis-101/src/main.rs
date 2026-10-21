// audit 12 probe j2: Validation list element writes in helpers, closures, through &mut Vec params; fill/rotate/sort
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use std::collections::HashMap;
type C = HashMap<String, String>;
const PEM: &[u8] = b"-----BEGIN PLACEHOLDER-----\nnot a key\n-----END PLACEHOLDER-----\n";
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn two() -> Validation { let mut v = Validation::new(Algorithm::RS256); v.algorithms.push(Algorithm::RS384); v }
fn mk_hs() -> Validation { let mut v = two(); v.algorithms[1] = Algorithm::HS256; v }
fn mk_rs() -> Validation { let mut v = two(); v.algorithms[1] = Algorithm::RS512; v }
fn set0(l: &mut Vec<Algorithm>) { l[0] = Algorithm::HS384; }
fn fill_hs(l: &mut [Algorithm]) { l.fill(Algorithm::HS256); }

fn main() {
    let t = arg(1);
    let dk = DecodingKey::from_rsa_pem(PEM).unwrap();
    let v1 = mk_hs();
    let _ = decode::<C>(&t, &dk, &v1);
    let v2 = mk_rs();
    let _ = decode::<C>(&t, &dk, &v2);
    let mut v3 = two();
    set0(&mut v3.algorithms);
    let _ = decode::<C>(&t, &dk, &v3);
    let mut v4 = two();
    let mut w = || v4.algorithms[0] = Algorithm::HS512;
    w();
    let _ = decode::<C>(&t, &dk, &v4);
    let mut v5 = two();
    fill_hs(&mut v5.algorithms);
    let _ = decode::<C>(&t, &dk, &v5);
    let mut v6 = two();
    v6.algorithms.fill(Algorithm::PS512);
    let _ = decode::<C>(&t, &dk, &v6);
    let mut v7 = two();
    v7.algorithms.rotate_left(1);
    v7.algorithms.sort_by_key(|a| *a as u8);
    let _ = decode::<C>(&t, &dk, &v7);
}
