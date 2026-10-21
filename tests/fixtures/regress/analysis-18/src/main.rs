// A program that draws no random number (third audit round): AES-256-GCM with a caller's key and
// nonce leaves rand_core and getrandom unused (their traits are only named). A digest inside
// `debug_assert!` and one compiled only with debug assertions are not in the release build the
// analysis looks at (`if cfg!(debug_assertions)` is a branch on `false`): sha2 is not used.
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let k = a[1].as_bytes();
    let c = Aes256Gcm::new_from_slice(&k[..32]).unwrap();
    let ct = c.encrypt(Nonce::from_slice(&k[32..44]), b"m".as_ref()).unwrap();
    let x = a.len();
    debug_assert!(Sha256::digest(x.to_le_bytes()).len() == 32);
    #[cfg(debug_assertions)]
    let _ = Sha256::digest(b"only in debug builds");
    println!("{} {x}", ct.len());
}
