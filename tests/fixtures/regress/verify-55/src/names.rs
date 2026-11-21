// A name written indirectly, for each kind of name the checks read: a macro, a derive, an
// attribute and a function-like procedural macro imported under another name; a trait object
// behind a type alias; a crate renamed in the source.
extern crate sha2 as hashes;

use mac::free_fn as ff;
use pm::Sum as S;
use pm::make_fn as mk;
use pm::wrapped as w;

pub trait Sum {
    fn sum(&self) -> Vec<u8>;
}

ff!(free2, Sha256);

#[derive(S)]
pub struct Blob2(pub Vec<u8>);

#[w]
pub fn wrapped2(d: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha384::digest(d).to_vec()
}

mk!(made2);

type DynH = dyn sha2::digest::DynDigest;

pub fn fed2(h: &mut DynH, d: &[u8]) {
    h.update(d);
}

pub fn renamed(d: &[u8]) -> Vec<u8> {
    use hashes::Digest;
    hashes::Sha512::digest(d).to_vec()
}

pub fn all(d: &[u8]) -> usize {
    let mut h = sha2::Sha224::default();
    fed2(&mut h, d);
    free2(d).len()
        + Blob2(d.to_vec()).sum().len()
        + wrapped2(d).len()
        + made2(d).len()
        + renamed(d).len()
}
