use ring::digest;
use sha2::{Digest, Sha512};

fn main() {
    let a = Sha512::digest(b"release notes");
    let b = digest::digest(&digest::SHA384, b"release notes");
    println!("{} {}", a.len(), b.as_ref().len());
}
