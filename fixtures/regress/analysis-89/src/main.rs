// round 12 regress (audit 11 probe pv3): key provenance after writes to other fields (cross-function generic, dyn through a parameter, 3 levels, a field write through a returned borrow), lookups
use ring::aead::{UnboundKey, AES_256_GCM};
use std::collections::HashMap;

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
struct K { key: [u8; 32], n: u64 }
struct M { k: K, tag: u8 }
struct O { m: M }
trait Bump { fn bump(&mut self); }
impl Bump for K { fn bump(&mut self) { self.n += 1; } }
impl Bump for M { fn bump(&mut self) { self.k.bump(); self.tag = 7; } }
impl K { fn n_mut(&mut self) -> &mut u64 { &mut self.n } }
fn from_args() -> K { let mut k = K { key: [0; 32], n: 0 }; k.key.copy_from_slice(&arg(1).as_bytes()[..32]); k }
fn dyn_bump(b: &mut dyn Bump) { b.bump() }
fn gen_bump<T: Bump>(t: &mut T) { t.bump() }

fn main() {
    let mut a = from_args();
    let b: &mut dyn Bump = &mut a;
    dyn_bump(b);
    let _ = UnboundKey::new(&AES_256_GCM, &a.key);
    let mut o = O { m: M { k: from_args(), tag: 0 } };
    gen_bump(&mut o.m);
    let _ = UnboundKey::new(&AES_256_GCM, &o.m.k.key);
    let mut c = from_args();
    *c.n_mut() = 9;
    let _ = UnboundKey::new(&AES_256_GCM, &c.key);
    let mut keys: HashMap<String, [u8; 32]> = HashMap::new();
    keys.insert("env".into(), from_args().key);
    let k = keys.get(&arg(2)).copied().unwrap_or([7u8; 32]);
    let _ = UnboundKey::new(&AES_256_GCM, &k);
    let lit: HashMap<&str, [u8; 32]> = HashMap::from([("a", [5u8; 32])]);
    let _ = UnboundKey::new(&AES_256_GCM, lit.get(arg(3).as_str()).unwrap());
    println!("{} {} {}", a.n, o.m.tag, c.n);
}
