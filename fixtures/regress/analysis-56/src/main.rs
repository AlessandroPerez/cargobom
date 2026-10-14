// audit 9 probe b3: key provenance after one write through `&mut self` to another field
use ring::aead::{UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
struct K { key: [u8; 32], n: usize }
impl K {
    fn bump(&mut self) { self.n += 7; }
}
fn fresh() -> K { let mut k = K { key: [0; 32], n: 0 }; SystemRandom::new().fill(&mut k.key).unwrap(); k }

fn main() {
    let mut a = K { key: [0; 32], n: 0 };
    a.key.copy_from_slice(&arg(1).as_bytes()[..32]);
    a.bump();
    let _ = UnboundKey::new(&AES_256_GCM, &a.key); // computed (args) only
    let mut b = fresh();
    b.bump();
    let _ = UnboundKey::new(&AES_256_GCM, &b.key); // random only
    println!("{}", a.n + b.n);
}
