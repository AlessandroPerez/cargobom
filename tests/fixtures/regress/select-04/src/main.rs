use sha2::{Digest, Sha256};

#[cfg(target_env = "musl")]
fn platform(data: &[u8]) -> Vec<u8> {
    sha3::Sha3_256::digest(data).to_vec()
}

#[cfg(not(target_env = "musl"))]
fn platform(data: &[u8]) -> Vec<u8> {
    md5::Md5::digest(data).to_vec()
}

fn main() {
    let input = std::env::args().nth(1).unwrap_or_default();
    println!("{} {:x?} {:x?}", env!("BUILD_ID"), Sha256::digest(input.as_bytes()), platform(input.as_bytes()));
}
