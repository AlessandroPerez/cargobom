use rand::Rng;
use sha2::{Digest, Sha256, Sha512};

pub enum Subset {
    All,
    Some(usize),
}

impl Subset {
    /// The library's API: generic over the packs, so no instance is in the library.
    pub fn apply<T: IntoIterator<Item = u64>>(self, packs: T) -> Vec<u64> {
        self.apply_with_rng(packs, &mut rand::thread_rng())
    }

    // private: `impl Rng` is `ThreadRng` at the only call there is, so the draw below is the
    // thread generator's (ChaCha12), whatever `packs` is
    fn apply_with_rng(
        self,
        packs: impl IntoIterator<Item = u64>,
        rng: &mut impl Rng,
    ) -> Vec<u64> {
        let mut packs: Vec<u64> = packs.into_iter().collect();
        if let Subset::Some(n) = self {
            while packs.len() > n {
                let i = rng.gen_range(0..packs.len());
                packs.swap_remove(i);
            }
        }
        packs
    }
}

/// Generic over the data and the hash: called by the library with two hashes, so the parameter
/// has no one type, and by nobody else.
fn checksum<D: Digest, T: AsRef<[u8]>>(data: T) -> Vec<u8> {
    D::digest(data.as_ref()).to_vec()
}

pub fn short<T: AsRef<[u8]>>(data: T) -> Vec<u8> {
    checksum::<Sha256, T>(data)
}

pub fn long<T: AsRef<[u8]>>(data: T) -> Vec<u8> {
    checksum::<Sha512, T>(data)
}

/// Public: any crate may call it with its own hash. The library's one call says nothing.
pub fn open_checksum<D: Digest, T: AsRef<[u8]>>(data: T) -> Vec<u8> {
    D::digest(data.as_ref()).to_vec()
}

pub fn default_checksum<T: AsRef<[u8]>>(data: T) -> Vec<u8> {
    open_checksum::<Sha256, T>(data)
}
