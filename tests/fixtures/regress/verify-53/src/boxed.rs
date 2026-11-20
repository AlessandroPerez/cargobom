//! rsa 0.9 (`Oaep::new::<T>`: `digest: Box::new(T::new())`): a value of the function's type
//! parameter is boxed as a trait object; the instance gives the type the line writes as `T`.

use sha2::digest::{Digest, DynDigest};

pub struct Padding {
    digest: Box<dyn DynDigest + Send + Sync>,
}

impl Padding {
    pub fn new<T: 'static + Digest + DynDigest + Send + Sync>() -> Self {
        Self {
            digest: Box::new(T::new()),
        }
    }

    pub fn label(mut self, label: &[u8]) -> Vec<u8> {
        self.digest.update(label);
        self.digest.finalize_reset().to_vec()
    }
}
