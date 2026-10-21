// Round 6 audit probe p1: two packages whose libraries share the crate name `md5` (md5 0.7,
// modelled, and md-5 0.10) in one build; sha2 0.11, a version the knowledge base does not cover,
// through digest 0.11; SHAKE256 through the XOF traits; HMAC over a hash of another package.
use hmac::Mac;
use md5rc::Digest as _;
use sha3::digest::{ExtendableOutput, Update, XofReader};

fn main() {
    // package md5 0.7 (crate md5): MD5, modelled
    let a = md5::compute(b"abc");
    // package md-5 0.10 (crate md5 too): unmodelled
    let b = md5rc::Md5::digest(b"abc");
    // sha2 0.11 (unsupported version) through digest 0.11
    let c = <sha2::Sha256 as sha2::Digest>::digest(b"abc");
    // SHAKE256 through the XOF traits of an unmodelled package
    let mut h = sha3::Shake256::default();
    Update::update(&mut h, b"abc");
    let mut r = h.finalize_xof();
    let mut out = [0u8; 32];
    r.read(&mut out);
    // HMAC over an unmodelled hash
    let mut m = hmac::Hmac::<md5rc::Md5>::new_from_slice(b"key").unwrap();
    Mac::update(&mut m, b"abc");
    let t = m.finalize().into_bytes();
    // a trait function named as a value, then called through the pointer
    let f = <sha3::Sha3_256 as sha3::Digest>::digest;
    let d = f(b"abc");
    println!("{:x} {:x} {:?} {:?} {:x} {:x}", a, b, c.as_slice(), out, t, d);
}
