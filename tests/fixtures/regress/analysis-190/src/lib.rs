use std::marker::PhantomData;

use sha2::{Digest, Sha256, Sha384, Sha512};
use sha3::Sha3_256;

/// A trait other crates can name: three hashes here, and what they implement it for.
pub trait Tagged {
    const TAG: u8;
}

impl Tagged for Sha256 {
    const TAG: u8 = 1;
}

impl Tagged for Sha384 {
    const TAG: u8 = 2;
}

impl Tagged for Sha512 {
    const TAG: u8 = 3;
}

pub struct Signer<D>(PhantomData<D>);

impl<D: Digest + Tagged> Signer<D> {
    pub fn new() -> Self {
        Signer(PhantomData)
    }

    // SHA-256, SHA-384 or SHA-512, beside another crate's
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let mut out = vec![D::TAG];
        out.extend(D::digest(data));
        out
    }

    pub fn verify(&self, data: &[u8], tag: &[u8]) -> bool {
        tag.first() == Some(&D::TAG) && framed::<D>(data) == tag[1..]
    }
}

// only this crate calls it, handing on its caller's parameter: what that one is
fn framed<D: Digest>(data: &[u8]) -> Vec<u8> {
    D::digest(data).to_vec()
}

mod sealed {
    pub trait Only {}
}

impl sealed::Only for Sha3_256 {}

// a trait only this crate can name, of one type: SHA3-256
pub fn fingerprint<D: Digest + sealed::Only>(data: &[u8]) -> Vec<u8> {
    D::digest(data).to_vec()
}

/// A trait every type implements bounds nothing.
pub trait Any {}

impl<T> Any for T {}

// the callers' hash
pub fn open<D: Digest + Any>(data: &[u8]) -> Vec<u8> {
    D::digest(data).to_vec()
}
