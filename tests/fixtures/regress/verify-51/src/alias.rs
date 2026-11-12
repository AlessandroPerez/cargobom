//! rustls-acme: an impl for the standard library's `Infallible` (`!` on this toolchain), which
//! the compiler prints `Config::<!>`, the defaulted second argument left out; and a field typed
//! by a generic alias of the file, whose method a call names.

use std::convert::Infallible;
use std::marker::PhantomData;

use sha2::{Digest, Sha512};

pub struct Config<EC, EA = EC>(PhantomData<(EC, EA)>, Hasher<'static>);

type Hasher<'a> = inner::Hasher<'a>;

mod inner {
    use sha2::Digest;

    pub struct Hasher<'a>(pub &'a [u8]);

    impl Hasher<'_> {
        pub fn digest(&self, data: &[u8]) -> Vec<u8> {
            let mut h = sha2::Sha384::new();
            h.update(self.0);
            h.update(data);
            h.finalize().to_vec()
        }
    }
}

impl Config<Infallible, Infallible> {
    pub fn new() -> Self {
        let salt = Sha512::digest(b"config");
        let salt: &'static [u8] = salt.to_vec().leak();
        Config(PhantomData, inner::Hasher(salt))
    }
}

impl<EC, EA> Config<EC, EA> {
    pub fn fingerprint(&self, data: &[u8]) -> Vec<u8> {
        self.1.digest(data)
    }
}
