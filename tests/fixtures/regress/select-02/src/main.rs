#[cfg(feature = "fast")]
fn checksum(data: &[u8]) -> Vec<u8> {
    blake3::hash(data).as_bytes().to_vec()
}

#[cfg(not(feature = "fast"))]
fn checksum(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).to_vec()
}

#[cfg(feature = "mac")]
fn tag(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    let mut m = Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

fn main() {
    let input = std::env::args().nth(1).unwrap_or_default();
    println!("{:x?}", checksum(input.as_bytes()));
    #[cfg(feature = "mac")]
    println!("{:x?}", tag(b"key from the environment", input.as_bytes()));
}
