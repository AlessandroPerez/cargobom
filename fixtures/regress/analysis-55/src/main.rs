// audit 9 probe b2: key provenance beside a cut chain of writes through `&mut self`
use ring::aead::{UnboundKey, AES_256_GCM};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
struct K { key: [u8; 32], n: usize }
impl K {
    fn bump(&mut self) { self.n += 1; }
    fn set(&mut self) { self.key = [3; 32]; }
    fn load(&mut self) { self.key.copy_from_slice(&arg(1).as_bytes()[..32]); }
}

fn main() {
    let mut a = K { key: [1; 32], n: 0 };
    a.bump(); a.bump(); a.bump(); a.bump(); a.bump(); a.bump();
    a.bump(); a.bump(); a.bump(); a.bump(); a.bump(); a.bump();
    let _ = UnboundKey::new(&AES_256_GCM, &a.key); // hard-coded [1; 32]: the search is cut
    let mut b = K { key: [1; 32], n: 0 };
    b.bump(); b.bump(); b.bump(); b.bump(); b.bump(); b.bump();
    b.bump(); b.bump(); b.bump(); b.bump(); b.bump(); b.bump();
    b.set();
    let _ = UnboundKey::new(&AES_256_GCM, &b.key); // hard-coded [3; 32], complete
    let mut c = K { key: [1; 32], n: 0 };
    c.bump(); c.bump(); c.bump(); c.bump(); c.bump(); c.bump();
    c.bump(); c.bump(); c.bump(); c.bump(); c.bump(); c.bump();
    c.load();
    let _ = UnboundKey::new(&AES_256_GCM, &c.key); // computed (args), complete
    println!("{}", a.n + b.n + c.n);
}
