use sha2::Digest;

lazy_static::lazy_static! {
    static ref EMPTY: Vec<u8> = sha2::Sha256::digest(b"").to_vec();
}

fn main() {
    let input = std::env::args().nth(1).unwrap_or_default().into_bytes();
    println!("{}", input == *EMPTY);
}
