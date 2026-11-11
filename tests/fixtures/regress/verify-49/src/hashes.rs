//! mail-auth: the hash types, whose impls are written in another module (`backend`).

pub struct Sha256;
pub struct Sha512;

pub trait HashImpl {
    fn hasher() -> ring::digest::Context;
}
