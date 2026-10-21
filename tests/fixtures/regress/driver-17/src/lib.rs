// A library's roots (third audit round): a generic public function runs its private,
// non-generic callee (password-auth's `generate_hash`); a public `async fn`'s body and a returned
// closure run when the caller awaits or calls them.
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::KeyInit;
use sha2::{Digest, Sha256};

/// Generic, as `password_auth::generate_hash` is: not itself a root, its callee is reached.
pub fn fingerprint(data: impl AsRef<[u8]>) -> Vec<u8> {
    inner(data.as_ref())
}

fn inner(d: &[u8]) -> Vec<u8> {
    Sha256::digest(d).to_vec()
}

/// An `async fn`: its body is a coroutine the root builds.
pub async fn seal(key: Vec<u8>) -> bool {
    Aes256Gcm::new_from_slice(&key).is_ok()
}

/// A returned closure: its body runs when the caller calls it.
pub fn sealer() -> impl Fn(&[u8]) -> bool {
    |key| aes_gcm::Aes128Gcm::new_from_slice(key).is_ok()
}
