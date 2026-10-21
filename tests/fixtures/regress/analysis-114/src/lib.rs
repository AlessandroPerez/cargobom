// audit 12 probe pl1: a library whose public generic API is also instantiated by its own monomorphic API
use ring::digest::{digest, Algorithm, SHA256, SHA512};
pub trait Pick { fn alg(&self) -> &'static Algorithm { &SHA256 } }
pub struct Fast;
impl Pick for Fast { fn alg(&self) -> &'static Algorithm { &SHA512 } }
pub fn hash<T: Pick>(t: &T, d: &[u8]) -> Vec<u8> { digest(t.alg(), d).as_ref().to_vec() }
pub fn hash_fast(d: &[u8]) -> Vec<u8> { hash(&Fast, d) }
pub fn hash_dyn(p: &dyn Pick, d: &[u8]) -> Vec<u8> { digest(p.alg(), d).as_ref().to_vec() }
pub fn hash_fast_dyn(d: &[u8]) -> Vec<u8> { hash_dyn(&Fast, d) }
