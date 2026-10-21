use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn main() {
    let mut mac = HmacSha256::new_from_slice(b"shared secret").unwrap();
    mac.update(b"order=42");
    let tag = mac.finalize().into_bytes();

    let mut check = HmacSha256::new_from_slice(b"shared secret").unwrap();
    check.update(b"order=42");
    println!("{}", check.verify_slice(&tag).is_ok());
}
