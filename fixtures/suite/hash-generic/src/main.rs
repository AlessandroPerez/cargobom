use sha2::{Digest, Sha224, Sha256, Sha512};

fn h<D: Digest>(data: &[u8]) -> Vec<u8> {
    D::digest(data).to_vec()
}

#[allow(dead_code)]
fn archive(data: &[u8]) -> Vec<u8> {
    h::<Sha512>(data)
}

fn main() {
    let short = h::<Sha224>(b"generic");
    let full = h::<Sha256>(b"generic");
    println!("{} {}", short.len(), full.len());
}
