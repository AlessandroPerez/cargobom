use md5::{Digest, Md5};

fn main() {
    // not built by `-p app`: no MD5 in the CBOM, no md-5 component
    let d = Md5::digest(b"tool");
    println!("{:x?} {:x?}", d, shared::unused(&d));
}
