// artifacts: each binary and the library's public API are walked apart, and an occurrence is
// tagged with those that reach it. `shared` runs in all three (its members reach it from both
// binaries); `only_lib` in the library's API alone.
use ring::digest::{digest, Algorithm, SHA512};
pub fn shared(a: &'static Algorithm, d: &[u8]) -> usize { digest(a, d).as_ref().len() } // SHA-256, SHA-384: bin one, bin two, lib d27
pub fn only_lib(d: &[u8]) -> usize { digest(&SHA512, d).as_ref().len() } // SHA-512: lib d27
