// round 11 regress (audit 10 probe pv2): a key from the arguments, another field bumped through a generic trait call
use ring::aead::{UnboundKey, AES_256_GCM};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
struct K { key: [u8; 32], n: u64 }
trait Bump { fn bump(&mut self); }
impl Bump for K { fn bump(&mut self) { self.n += 1; } }
fn from_args() -> K { let mut k = K { key: [0; 32], n: 0 }; k.key.copy_from_slice(&arg(1).as_bytes()[..32]); k }
fn gen_bump<T: Bump>(t: &mut T) { t.bump() }

fn main() {
    let mut k6 = from_args();
    gen_bump(&mut k6);
    let _ = UnboundKey::new(&AES_256_GCM, &k6.key); // computed only
    println!("{}", k6.n);
}
