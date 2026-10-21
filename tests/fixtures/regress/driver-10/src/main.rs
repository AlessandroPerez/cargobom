use aes_gcm::aead::KeyInit;
use aes_gcm::Aes256Gcm;

fn main() {
    let k: [u8; 32] = std::env::args().count().to_le_bytes().repeat(4).try_into().unwrap();
    let c = parking_lot::Mutex::new(Aes256Gcm::new_from_slice(&k).unwrap());
    let g = c.lock();
    drop(g);
}
