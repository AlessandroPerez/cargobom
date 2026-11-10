// Two impls of one trait, each with its own associated type (jwt-compact's `Hs256`, `Hs384`):
// `key.mac(m)` in `impl Alg for A384` is called on a `Key384`, that impl's `type Key`, and
// instantiates `Key384::mac`; the first `type Key = ..;` of the file is another impl's. The
// verifier reads `Self::Key` in the impl around the call, so each instantiation detail is at
// its own call and a detail moved to the other impl's call is rejected.
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384};

struct Key256(Vec<u8>);
struct Key384(Vec<u8>);

impl Key256 {
    fn mac(&self, m: impl AsRef<[u8]>) -> Vec<u8> {
        let mut h = Hmac::<Sha256>::new_from_slice(&self.0).unwrap();
        h.update(m.as_ref());
        h.finalize().into_bytes().to_vec()
    }
}

impl Key384 {
    fn mac(&self, m: impl AsRef<[u8]>) -> Vec<u8> {
        let mut h = Hmac::<Sha384>::new_from_slice(&self.0).unwrap();
        h.update(m.as_ref());
        h.finalize().into_bytes().to_vec()
    }
}

trait Alg {
    type Key;
    fn sign(&self, key: &Self::Key, m: &[u8]) -> Vec<u8>;
}

struct A256;
struct A384;

impl Alg for A256 {
    type Key = Key256;
    fn sign(&self, key: &Self::Key, m: &[u8]) -> Vec<u8> {
        key.mac(m)
    }
}

impl Alg for A384 {
    type Key = Key384;
    fn sign(&self, key: &Self::Key, m: &[u8]) -> Vec<u8> {
        key.mac(m)
    }
}

fn main() {
    let a = A256.sign(&Key256(vec![1; 32]), b"m");
    let b = A384.sign(&Key384(vec![2; 48]), b"m");
    println!("{} {}", a.len(), b.len());
}
