use sha2::{Digest, Sha384};

// The attribute wraps the body in a closure it calls. The closure is named at the attribute,
// and the function builds it there, above its own first line.
#[pm::traced]
pub fn derive_key(seed: &[u8]) -> Vec<u8> {
    let mut h = Sha384::new();
    h.update(seed);
    h.finalize().to_vec()
}

// In a generic function: the closure's instance is made where the function's is, and the
// function is cited at the attribute, which is on it.
#[pm::traced]
pub fn hash_with<D: Digest>(data: &[u8]) -> Vec<u8> {
    D::digest(data).to_vec()
}
