//! rust-s3 (`Request::presigned_authorization`): a trait's default `async` method, its body run
//! for the type that implements the trait. The occurrence is in the trait's method's body, the
//! chain names that body's instance for the type.

use hmac::{Hmac, Mac};
use sha2::Sha256;

pub trait Request {
    fn key(&self) -> Vec<u8>;

    async fn authorization(&self, data: &[u8]) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key()).unwrap();
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    async fn presigned(&self) -> Vec<u8> {
        self.authorization(b"presigned").await
    }
}

pub struct Bucket(pub Vec<u8>);

impl Request for Bucket {
    fn key(&self) -> Vec<u8> {
        self.0.clone()
    }
}

pub async fn sign(b: &Bucket) -> Vec<u8> {
    b.presigned().await
}
