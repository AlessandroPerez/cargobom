// audit 13 probe jl2: encode headers from containers, other key families, dead writers, witnesses, static arrays
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use std::collections::HashMap;
type C = HashMap<String, String>;
const PEM: &[u8] = b"-----BEGIN PLACEHOLDER-----\nnot a key\n-----END PLACEHOLDER-----\n";
static RS_S: [Algorithm; 2] = [Algorithm::RS256, Algorithm::RS384];
static MIX: &[Algorithm] = &[Algorithm::RS256, Algorithm::HS256];
const RS_C: [Algorithm; 2] = [Algorithm::PS256, Algorithm::PS384];
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn add(l: &mut Vec<Algorithm>, a: Algorithm) { l.push(a); }
fn fix(v: &mut Validation) { v.algorithms[0] = Algorithm::RS384; }
struct App { v: Validation }
impl App { fn set(&mut self) { self.v.algorithms[0] = Algorithm::PS512; } }
#[allow(dead_code)]
fn dead() { let mut w = Validation::new(Algorithm::RS256); add(&mut w.algorithms, Algorithm::HS256); let _ = w; }

fn main() {
    let t = arg(1);
    let i = arg(2).len();
    let ek = EncodingKey::from_secret(b"k");
    let h1 = Header::new([Algorithm::HS256, Algorithm::RS256][i % 2]);
    let _ = encode(&h1, &1u8, &ek);
    let algs = vec![Algorithm::HS384, Algorithm::ES256];
    let mut h2 = Header::default();
    h2.alg = algs[i % 2];
    let _ = encode(&h2, &1u8, &ek);
    let dk = DecodingKey::from_rsa_pem(PEM).unwrap();
    let mut v1 = Validation::new(Algorithm::RS256);
    add(&mut v1.algorithms, Algorithm::RS512);
    let _ = decode::<C>(&t, &dk, &v1);
    let mut v2 = Validation::new(Algorithm::RS256);
    fix(&mut v2);
    let _ = decode::<C>(&t, &dk, &v2);
    let mut app = App { v: Validation::new(Algorithm::RS256) };
    app.set();
    let _ = decode::<C>(&t, &dk, &app.v);
    let mut v3 = Validation::new(Algorithm::RS256);
    v3.algorithms = RS_S.to_vec();
    let _ = decode::<C>(&t, &dk, &v3);
    let mut v4 = Validation::new(Algorithm::RS256);
    v4.algorithms = MIX.to_vec();
    let _ = decode::<C>(&t, &dk, &v4);
    let mut v5 = Validation::new(Algorithm::RS256);
    v5.algorithms = RS_C.iter().copied().collect();
    let _ = decode::<C>(&t, &dk, &v5);
    let mut v6 = Validation::new(Algorithm::RS256);
    v6.algorithms = Vec::from(RS_S);
    let _ = decode::<C>(&t, &dk, &v6);
    let ek2 = DecodingKey::from_ec_pem(PEM).unwrap();
    let mut v7 = Validation::new(Algorithm::ES256);
    v7.algorithms.push(Algorithm::EdDSA);
    let _ = decode::<C>(&t, &ek2, &v7);
    let sk = DecodingKey::from_secret(b"k");
    let mut v8 = Validation::default();
    v8.algorithms.push(Algorithm::HS512);
    let _ = decode::<C>(&t, &sk, &v8);
    let mut v9 = Validation::default();
    v9.algorithms.push(Algorithm::RS256);
    let _ = decode::<C>(&t, &sk, &v9);
    let mut v10 = Validation::new(Algorithm::RS256);
    let mut f = |v: &mut Validation| v.algorithms[0] = Algorithm::RS512;
    f(&mut v10);
    let _ = decode::<C>(&t, &dk, &v10);
}
