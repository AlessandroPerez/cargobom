// A nonce written whole by `copy_from_slice` into one half of a caller's zeroed buffer
// (`split_at_mut`), then read through the same borrow: its provenance is the copied value,
// not the buffer's zero initializer (boringtun's cookie reply).
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};

struct Limiter {
    key: [u8; 32],
    ctr: u64,
}

impl Limiter {
    fn nonce(&self) -> [u8; 24] {
        let h = Sha256::digest(self.ctr.to_le_bytes());
        let mut n = [0u8; 24];
        n.copy_from_slice(&h[..24]);
        n
    }

    fn seal(&self, dst: &mut [u8]) {
        let (nonce, rest) = dst.split_at_mut(24);
        nonce.copy_from_slice(&self.nonce()[..]);
        let (tag_place, body) = rest.split_at_mut(16);
        let cipher = XChaCha20Poly1305::new_from_slice(&self.key).unwrap();
        let iv = XNonce::from_slice(nonce);
        let tag = cipher.encrypt_in_place_detached(iv, b"", body).unwrap();
        tag_place.copy_from_slice(&tag);
    }
}

fn main() {
    let key: [u8; 32] = Sha256::digest(std::env::args().collect::<String>()).into();
    let l = Limiter {
        key,
        ctr: std::env::args().count() as u64,
    };
    let mut out = [0u8; 64];
    l.seal(&mut out);
    println!("{:02x?}", &out[..4]);
}
