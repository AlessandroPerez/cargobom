use sha2::{Digest, Sha256};

struct Tag;

const ROUNDS: [u32; 2] = [0x6a09_e667, 0xbb67_ae85];

const fn mix(i: usize) -> u32 {
    ROUNDS[i].rotate_left(7) ^ ROUNDS[i].rotate_right(3)
}

impl Tag {
    // (an associated constant is evaluated only where code uses it, and this one's evaluation
    // could fail, at the index: the driver does not evaluate it, and looks instead at what
    // its body and the `const fn`s it calls name)
    const MID: u32 = mix(1);
}

fn main() {
    let input = std::env::args().nth(1).unwrap_or_default().into_bytes();
    let mut h = Sha256::new();
    h.update(Tag::MID.to_le_bytes());
    h.update(&input);
    println!("{:x}", h.finalize());
}
