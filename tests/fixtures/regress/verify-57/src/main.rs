use hmac::digest::InvalidLength;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

fn mac_of<M: Mac>(
    key: &[u8],
    data: &[u8],
    new: fn(&[u8]) -> Result<M, InvalidLength>,
) -> Option<Vec<u8>> {
    let mut mac = new(key).ok()?;
    mac.update(data);
    Some(mac.finalize().into_bytes().to_vec())
}

pub fn mac(bits: u16, key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    match bits {
        256 => mac_of(key, data, Hmac::<Sha256>::new_from_slice),
        512 => mac_of(key, data, Hmac::<Sha512>::new_from_slice),
        _ => None,
    }
}

pub fn hashes(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let h = Sha256::digest;
    let g = Sha512::digest;
    (h(data).to_vec(), g(data).to_vec())
}

fn main() {
    let data = std::env::args().nth(1).unwrap_or_default();
    let key = std::env::args().nth(2).unwrap_or_default();
    let a = mac(if data.len() > 8 { 512 } else { 256 }, key.as_bytes(), data.as_bytes());
    let (b, c) = hashes(data.as_bytes());
    println!("{:?} {} {}", a.map(|m| m.len()), b.len(), c.len());
}
