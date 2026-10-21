// impls on arrays and tuples, a `From` of an array, a const generic impl; the same digest in
// `format!` in two functions
use sha2::{Digest, Sha256, Sha512};

fn first<D: Digest>(d: &[u8]) -> String {
    format!("{:x}", D::digest(d).len())
}

fn second<D: Digest>(d: &[u8]) -> String {
    format!("{:x}", D::digest(d).len())
}

trait Fingerprint {
    fn fingerprint(&self) -> usize;
}
impl Fingerprint for [u8; 4] {
    fn fingerprint(&self) -> usize {
        Sha256::digest(self).len()
    }
}
impl Fingerprint for (u8, u8) {
    fn fingerprint(&self) -> usize {
        Sha512::digest([self.0, self.1]).len()
    }
}

trait Hx {
    fn hx(&self) -> usize;
}
impl<const N: usize> Hx for [u16; N] {
    fn hx(&self) -> usize {
        Sha512::digest([self.len() as u8]).len()
    }
}

pub struct Key(usize);
impl From<[u8; 32]> for Key {
    fn from(b: [u8; 32]) -> Key {
        Key(Sha256::digest(b).len())
    }
}

pub fn run(d: &[u8]) -> usize {
    let k: Key = [7u8; 32].into();
    let v = [1u8, 2, 3, 4];
    first::<Sha256>(d).len() + second::<Sha512>(d).len() + v.fingerprint() + (1u8, 2u8).fingerprint() + [1u16, 2].hx() + k.0
}
