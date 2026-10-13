use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};

fn main() {
    let key = Key::<Aes256Gcm>::from_slice(&[7u8; 32]);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&[1u8; 12]);
    let ct = cipher.encrypt(nonce, b"attack at dawn".as_ref()).unwrap();
    let pt = cipher.decrypt(nonce, ct.as_ref()).unwrap();
    println!("{} {}", ct.len(), pt.len());
}
