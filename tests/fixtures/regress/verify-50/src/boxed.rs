//! pgp (`HashAlgorithm::new_hasher`): hashers boxed as `Box::<T>::default()`, the type named
//! in the box's own arguments by a path; one of them an alias only a macro of its crate
//! defines (sha3's `impl_sha3!(Sha3_256Core, Sha3_256, ..)`).

use sha2::digest::DynDigest;

pub fn new_hasher(kind: u8) -> Box<dyn DynDigest + Send> {
    match kind {
        0 => Box::<sha2::Sha256>::default(),
        _ => Box::<sha3::Sha3_256>::default(),
    }
}

pub fn hash(kind: u8, data: &[u8]) -> Box<[u8]> {
    let mut hasher = new_hasher(kind);
    hasher.update(data);
    hasher.finalize()
}
