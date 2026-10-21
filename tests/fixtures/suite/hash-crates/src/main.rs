use md5::Md5;
use sha3::{Digest, Sha3_256};

fn main() {
    let a = Sha3_256::digest(b"keccak");
    let mut h = Md5::new();
    h.update(b"legacy ");
    h.update(b"etag");
    let b = h.finalize();
    println!("{} {}", a.len(), b.len());
}
