// audit 13 probe jl4: a list's one value read from tables, statics, struct fields (alternatives, not co-members)
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use std::collections::HashMap;
use std::sync::Mutex;
type C = HashMap<String, String>;
const PEM: &[u8] = b"-----BEGIN PLACEHOLDER-----\nnot a key\n-----END PLACEHOLDER-----\n";
static ALGS: [Algorithm; 2] = [Algorithm::RS256, Algorithm::HS256];
const CALGS: [Algorithm; 2] = [Algorithm::RS384, Algorithm::HS384];
struct Cfg { alg: Algorithm }
static CFG: Mutex<Cfg> = Mutex::new(Cfg { alg: Algorithm::PS256 });
static TCFG: [Cfg; 2] = [Cfg { alg: Algorithm::PS384 }, Cfg { alg: Algorithm::HS512 }];
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn set_hs() { CFG.lock().unwrap().alg = Algorithm::HS256; }

fn main() {
    let t = arg(1);
    let i = arg(2).len() % 2;
    if i == 1 { set_hs(); }
    let dk = DecodingKey::from_rsa_pem(PEM).unwrap();
    let v1 = Validation::new(ALGS[i]);
    let _ = decode::<C>(&t, &dk, &v1);
    let v2 = Validation::new(CALGS[i]);
    let _ = decode::<C>(&t, &dk, &v2);
    let v3 = Validation::new(CFG.lock().unwrap().alg);
    let _ = decode::<C>(&t, &dk, &v3);
    let v4 = Validation::new(TCFG[i].alg);
    let _ = decode::<C>(&t, &dk, &v4);
    let c = if i == 0 { Cfg { alg: Algorithm::RS512 } } else { Cfg { alg: Algorithm::ES256 } };
    let v5 = Validation::new(c.alg);
    let _ = decode::<C>(&t, &dk, &v5);
}
