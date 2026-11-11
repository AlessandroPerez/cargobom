//! biscuit-auth (`#[derive(.., Hash, Eq)]` on its `PublicKey`): a derive of the language cites
//! the call it makes for a field at the trait's name in the attribute. The line below is no
//! such call, whatever the type's body holds further on.

use std::hash::{Hash, Hasher};

use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Inner(pub [u8; 4]);

impl Hash for Inner {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Sha256::digest(self.0).as_slice().hash(state);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Key {
    Plain(Inner),
    Tagged(u8),
}

pub fn slot(key: &Key) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut hasher);
    hasher.finish()
}
