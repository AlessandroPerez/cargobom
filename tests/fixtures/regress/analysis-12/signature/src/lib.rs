use hmac::{Hmac, Mac};
use sha2::Sha256;

// L1: a hard-coded key in the member's code
pub fn tag(d: &[u8]) -> Vec<u8> {
    let mut m = Hmac::<Sha256>::new_from_slice(b"hard-coded key").unwrap();
    m.update(d);
    m.finalize().into_bytes().to_vec()
}
