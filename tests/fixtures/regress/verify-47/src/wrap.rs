//! magic-wormhole and its noise-rust-crypto.

use sha2::Digest;

// a derive on a tuple struct written on one line, under another attribute: the derived
// `Default` runs `sha2::Sha256::default()` for the field, which is on the struct's own line
#[cfg(not(feature = "none"))]
#[derive(Default, Clone)]
pub struct Sha256(sha2::Sha256);

pub fn digest(data: &[u8]) -> Vec<u8> {
    let mut h = Sha256::default();
    h.0.update(data);
    h.0.finalize().to_vec()
}

pub trait Init {
    fn leader(&self) -> Box<dyn Finalizer>;
}

pub trait Finalizer {
    fn finalize(&self, data: &[u8]) -> Vec<u8>;
}

pub struct NoiseInit;

impl Init for NoiseInit {
    fn leader(&self) -> Box<dyn Finalizer> {
        let make = || {
            // a type and its impl inside a closure of a method:
            // `<<NoiseInit as Init>::leader::{closure#0}::Fin as Finalizer>::finalize`
            struct Fin;
            impl Finalizer for Fin {
                fn finalize(&self, data: &[u8]) -> Vec<u8> {
                    sha2::Sha224::digest(data).to_vec()
                }
            }
            Fin
        };
        Box::new(make())
    }
}

pub fn leader(data: &[u8]) -> Vec<u8> {
    NoiseInit.leader().finalize(data)
}
