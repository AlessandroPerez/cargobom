//! hpke: the other name imported from the file that gives it.

use crate::kdf::{self, KdfTrait};
use sha2::Digest;

pub struct Suite;

// `<Suite as Kdf>::extract`, written with a name another file of the package made
impl KdfTrait for Suite {
    fn extract(ikm: &[u8]) -> Vec<u8> {
        sha2::Sha384::digest(ikm).to_vec()
    }
}

pub fn suite(ikm: &[u8]) -> Vec<u8> {
    kdf::run::<Suite>(ikm)
}
