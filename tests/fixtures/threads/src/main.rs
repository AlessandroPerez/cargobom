//! rcbom fixture: crypto reached only through std's thread machinery, a boxed `dyn FnOnce` and
//! a fn pointer. Every finding here must be reachable. Expected findings: ../expected.txt.
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

fn hash(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

fn mac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

fn main() {
    // a spawned thread
    let t = std::thread::spawn(|| hash(b"in a thread"));
    let a = t.join().unwrap();
    // a boxed closure called through `dyn FnOnce`
    let f: Box<dyn FnOnce() -> Vec<u8>> = Box::new(|| mac(b"k", b"boxed"));
    let b = f();
    // a fn pointer
    let g: fn(&[u8]) -> Vec<u8> = hash;
    let c = g(b"pointer");
    println!("{} {} {}", a.len(), b.len(), c.len());
}
