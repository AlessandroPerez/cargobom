use sha2::{Digest, Sha256};

fn main() {
    println!("{:x?}", Sha256::digest(b"built with the feature"));
}
