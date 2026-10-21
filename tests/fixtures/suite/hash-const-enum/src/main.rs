use ring::digest;
use sha2::{Digest, Sha256, Sha512};

#[allow(dead_code)]
enum Mode {
    Fast,
    Strong,
}

const MODE: Mode = Mode::Fast;

fn main() {
    let alg = match MODE {
        Mode::Fast => &digest::SHA256,
        Mode::Strong => &digest::SHA512,
    };
    let a = digest::digest(alg, b"const enum");
    let b = match MODE {
        Mode::Fast => Sha256::digest(b"const enum").to_vec(),
        Mode::Strong => Sha512::digest(b"const enum").to_vec(),
    };
    println!("{} {}", a.as_ref().len(), b.len());
}
