//! The program's own crate holding a function of the modelled crate: named here.

pub static PICKED: fn(Vec<u8>) -> md5::Digest = md5::compute::<Vec<u8>>;
