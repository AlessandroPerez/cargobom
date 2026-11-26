use md5::{Digest, Md5};

fn main() {
    println!("{:x?}", Md5::digest(b"always built"));
}
