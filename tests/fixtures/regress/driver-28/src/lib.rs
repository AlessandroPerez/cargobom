// a library's generic functions its users can call, which it does not instantiate itself: a
// call there whose types are the function's parameters is kept, with the algorithm its types
// name or else an unknown one its callers choose; where an instance of the library's own
// shows the call, the instance's algorithm stands alone
use aes_gcm::aead::{Aead, AeadCore, Nonce};
use hmac::{Hmac, Mac};
use rand::seq::SliceRandom;
use sha2::{Digest, Sha256, Sha512};

pub fn h(d: impl AsRef<[u8]>) -> Vec<u8> {
    Sha256::digest(d).to_vec() // SHA-256: the parameter is the data
}

pub fn s<R: rand::Rng>(v: &mut [u8], r: &mut R) {
    v.shuffle(r); // an unknown generator, the caller's
}

pub fn e<A: Aead + AeadCore>(a: &A, n: &Nonce<A>, m: &[u8]) -> Vec<u8> {
    a.encrypt(n, m).unwrap_or_default() // an unknown AEAD, the caller's
}

pub fn t(v: impl IntoIterator<Item = u8>) -> Vec<u8> {
    let mut v: Vec<u8> = v.into_iter().collect();
    v.shuffle(&mut rand::thread_rng()); // ChaCha12-RNG
    v
}

pub fn c<T: AsRef<[u8]>>(v: &[T]) -> Vec<Vec<u8>> {
    v.iter().map(|x| Sha256::digest(x).to_vec()).collect() // SHA-256, in a closure
}

pub fn mac<M: Mac + hmac::digest::KeyInit>(k: &[u8], d: &[u8]) -> Vec<u8> {
    let mut m = <M as Mac>::new_from_slice(k).unwrap();
    m.update(d); // HMAC-SHA-256 only: the library's own instance
    m.finalize().into_bytes().to_vec() // HMAC-SHA-256 only
}

pub fn mac256(k: &[u8], d: &[u8]) -> Vec<u8> {
    mac::<Hmac<Sha256>>(k, d)
}

fn inner<D: Digest>(d: &[u8]) -> Vec<u8> {
    D::digest(d).to_vec() // SHA-512 only: no user can choose D
}

pub fn sha512(d: &[u8]) -> Vec<u8> {
    inner::<Sha512>(d)
}
