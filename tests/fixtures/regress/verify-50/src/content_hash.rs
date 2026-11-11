//! jj-core's `ContentHash`: a trait and the derive of its name, generic impls over slices,
//! vectors and maps.

use std::collections::BTreeMap;

use sha2::digest::Update;
use sha2::{Digest, Sha512};

pub use pm::ContentHash;

pub trait ContentHash {
    fn hash(&self, state: &mut impl Update);
}

pub fn sha512_hash(x: &(impl ContentHash + ?Sized)) -> Vec<u8> {
    let mut hasher = Sha512::default();
    x.hash(&mut hasher);
    hasher.finalize().to_vec()
}

impl ContentHash for u8 {
    fn hash(&self, state: &mut impl Update) {
        state.update(&[*self]);
    }
}

impl ContentHash for i64 {
    fn hash(&self, state: &mut impl Update) {
        state.update(&self.to_le_bytes());
    }
}

// an impl for every slice: `impl ContentHash for [?]` is the one of `[CommitId]`
impl<T: ContentHash> ContentHash for [T] {
    fn hash(&self, state: &mut impl Update) {
        state.update(&(self.len() as u64).to_le_bytes());
        for x in self {
            x.hash(state);
        }
    }
}

impl<T: ContentHash> ContentHash for Vec<T> {
    fn hash(&self, state: &mut impl Update) {
        self.as_slice().hash(state);
    }
}

// two calls of one method name on two variables a pattern binds: which of them is the key's
// `hash` the text does not say, and each is one of that range
impl<K: ContentHash, V: ContentHash> ContentHash for BTreeMap<K, V> {
    fn hash(&self, state: &mut impl Update) {
        state.update(&(self.len() as u64).to_le_bytes());
        for (k, v) in self {
            k.hash(state);
            v.hash(state);
        }
    }
}
