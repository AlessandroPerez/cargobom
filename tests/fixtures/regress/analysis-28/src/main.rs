// RustCrypto trait operations on types of packages the knowledge base does not model, through
// the traits below `Digest` (round 6 audit, H4 and H8): SHAKE256 through `Update`,
// `ExtendableOutput` and `XofReader`; a BLAKE2b MAC set up with `Mac::new_from_slice` (a MAC,
// not a hash) and used with `update` and `finalize`.
use blake2::digest::{ExtendableOutput, Mac, Update, XofReader};
use blake2::Blake2bMac512;
use sha3::Shake256;

fn main() {
    let d = std::env::args().next().unwrap_or_default().into_bytes();
    let mut x = Shake256::default();
    x.update(&d);
    let mut r = x.finalize_xof();
    let mut out = [0u8; 64];
    r.read(&mut out);
    let mut m = <Blake2bMac512 as Mac>::new_from_slice(b"key").unwrap();
    Mac::update(&mut m, &d);
    let t = m.finalize().into_bytes();
    println!("{} {}", out.len(), t.len());
}
