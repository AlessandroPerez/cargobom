use sha2::{Digest, Sha256};

fn main() {
    let input = std::env::args().nth(1).unwrap_or_default();
    // SHA-256: the selected member's own call
    let d = Sha256::digest(input.as_bytes());
    // SHA-512 inside `shared::fingerprint`, which this binary reaches
    let f = shared::fingerprint(&d);
    println!("{f:x?}");
}
