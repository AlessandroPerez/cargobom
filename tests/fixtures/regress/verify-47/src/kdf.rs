//! hpke: a trait used under another name, because a type parameter takes its own.

use sha2::Digest;

pub trait Kdf {
    fn extract(ikm: &[u8]) -> Vec<u8>;
}

// (`Kdf` is a type parameter's name below)
pub(crate) use Kdf as KdfTrait;

pub struct HkdfSha256;
pub struct HkdfSha512;

// the impl's header names the trait by its other name: `<HkdfSha256 as Kdf>::extract`
impl KdfTrait for HkdfSha256 {
    fn extract(ikm: &[u8]) -> Vec<u8> {
        two_stage::extract::<sha2::Sha256>(ikm)
    }
}

impl KdfTrait for HkdfSha512 {
    fn extract(ikm: &[u8]) -> Vec<u8> {
        two_stage::extract::<sha2::Sha512>(ikm)
    }
}

pub mod two_stage {
    use super::Digest;

    pub fn extract<D: Digest>(ikm: &[u8]) -> Vec<u8> {
        D::digest(ikm).to_vec()
    }
}

pub fn run<Kdf: KdfTrait>(ikm: &[u8]) -> Vec<u8> {
    Kdf::extract(ikm)
}

pub fn both(ikm: &[u8]) -> (Vec<u8>, Vec<u8>) {
    (run::<HkdfSha256>(ikm), run::<HkdfSha512>(ikm))
}
