// round 11 regress (audit 10 probe pv1): key provenance after writes into fields by methods (several fields, nested,
// strong / weak, trait methods static / generic / dyn)
use ring::aead::{UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
struct K { key: [u8; 32], salt: [u8; 16], n: u64 }
struct Outer { inner: K, tag: u8 }
trait Bump { fn bump(&mut self); }
impl Bump for K { fn bump(&mut self) { self.n += 1; self.salt = [4; 16]; } }
trait Rekey { fn rekey2(&mut self); }
impl Rekey for K { fn rekey2(&mut self) { SystemRandom::new().fill(&mut self.key).unwrap(); } }
impl K {
    fn rekey(&mut self) { SystemRandom::new().fill(&mut self.key).unwrap(); self.salt = [9; 16]; self.n += 1; }
    fn maybe(&mut self, b: bool) { if b { self.key.copy_from_slice(&arg(5).as_bytes()[..32]); } }
}
impl Outer { fn refresh(&mut self) { self.inner.rekey(); self.tag = 3; } }
fn from_args() -> K { let mut k = K { key: [0; 32], salt: [0; 16], n: 0 }; k.key.copy_from_slice(&arg(1).as_bytes()[..32]); k }
fn gen_bump<T: Bump>(t: &mut T) { t.bump() }

fn main() {
    let mut k1 = K { key: [5; 32], salt: [0; 16], n: 0 };
    k1.rekey();
    let _ = UnboundKey::new(&AES_256_GCM, &k1.key); // random only
    let mut o2 = Outer { inner: K { key: [6; 32], salt: [0; 16], n: 0 }, tag: 0 };
    o2.refresh();
    let _ = UnboundKey::new(&AES_256_GCM, &o2.inner.key); // random only
    let mut k3 = K { key: [7; 32], salt: [0; 16], n: 0 };
    k3.maybe(arg(3).is_empty());
    let _ = UnboundKey::new(&AES_256_GCM, &k3.key); // hard-coded or computed
    let mut k4 = K { key: [8; 32], salt: [0; 16], n: 0 };
    k4.rekey2();
    let _ = UnboundKey::new(&AES_256_GCM, &k4.key); // random only
    let mut k5 = from_args();
    k5.bump();
    let _ = UnboundKey::new(&AES_256_GCM, &k5.key); // computed only
    let mut k6 = from_args();
    gen_bump(&mut k6);
    let _ = UnboundKey::new(&AES_256_GCM, &k6.key); // computed only
    let mut k7 = from_args();
    { let b: &mut dyn Bump = &mut k7; b.bump(); }
    let _ = UnboundKey::new(&AES_256_GCM, &k7.key); // computed only
    println!("{} {} {} {}", k1.n, k5.n + k6.n + k7.n, o2.tag, k3.salt[0] + k4.salt[0]);
}
