//! atuin (reqwest's `connect.rs`): one method name three times down a chain, each another
//! type's, only the middle one a crypto package's (sha1_smol, which the knowledge base does
//! not model). The position is one of that range, and a shift of it onto a neighbour confirms
//! nothing.

use sha1_smol::Sha1;

pub struct Outer(pub Sha1);

impl Outer {
    pub fn digest(&self) -> &Sha1 {
        &self.0
    }
}

pub trait Bytes {
    fn digest(&self) -> [u8; 20];
}

impl Bytes for sha1_smol::Digest {
    fn digest(&self) -> [u8; 20] {
        self.bytes()
    }
}

pub fn peer(outer: &Outer) -> [u8; 20] {
    outer
        .digest()
        .digest()
        .digest()
}
