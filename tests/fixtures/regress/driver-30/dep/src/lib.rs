// a dependency's functions, reached only through the generic public functions of the library
// that uses it (ssh-key's `PrivateKey::decrypt(&self, password: impl AsRef<[u8]>)` calling
// ssh-cipher's `Cipher::decrypt`)
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

pub fn hash224(d: &[u8]) -> Vec<u8> {
    Sha224::digest(d).to_vec() // reachable: called from the library's `direct`
}

pub fn hash_any<T: AsRef<[u8]>>(d: T) -> Vec<u8> {
    inner384(d.as_ref())
}

fn inner384(d: &[u8]) -> Vec<u8> {
    Sha384::digest(d).to_vec() // reachable: through `hash_any`, which `nested` calls
}

pub fn hash256(d: &[u8]) -> Vec<u8> {
    Sha256::digest(d).to_vec() // reachable: from the closure in `in_closure`
}

pub fn unused512(d: &[u8]) -> Vec<u8> {
    Sha512::digest(d).to_vec() // present: the library never calls it
}
