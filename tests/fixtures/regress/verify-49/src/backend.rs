//! mail-auth: impls for types of another module. The contexts `complete` finishes come from
//! `backend::<impl HashImpl for hashes::Sha256>::hasher` and its neighbour: functions the
//! module has only inside those impls.

use ring::digest::{Context, SHA256, SHA512};
use sha2::Digest;

use crate::hashes::{HashImpl, Sha256, Sha512};

impl HashImpl for Sha256 {
    fn hasher() -> Context {
        Context::new(&SHA256)
    }
}

impl HashImpl for Sha512 {
    fn hasher() -> Context {
        Context::new(&SHA512)
    }
}

pub trait HashContext {
    fn complete(self) -> Vec<u8>;
}

impl HashContext for Context {
    fn complete(self) -> Vec<u8> {
        self.finish().as_ref().to_vec()
    }
}

pub struct ShortKey;
pub struct LongKey;

pub trait Sign {
    fn sign<T: AsRef<[u8]>>(&self, data: T) -> Vec<u8>;
}

impl Sign for ShortKey {
    fn sign<T: AsRef<[u8]>>(&self, data: T) -> Vec<u8> {
        sha2::Sha224::digest(data.as_ref()).to_vec()
    }
}

impl Sign for LongKey {
    fn sign<T: AsRef<[u8]>>(&self, data: T) -> Vec<u8> {
        sha2::Sha384::digest(data.as_ref()).to_vec()
    }
}
