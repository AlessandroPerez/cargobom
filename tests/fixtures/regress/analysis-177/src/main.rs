// blake2 0.10: the hashes by their output size (`Blake2s256`, `Blake2b512`, a `Blake2b<U32>`),
// the keyed mode `Blake2sMac<OutSize>` (which the registry names `-HMAC`), an HMAC over BLAKE2s
// (WireGuard's, boringtun), and a hash whose size is chosen at run time (`Blake2bVar`), named
// by its family only.
use blake2::digest::consts::{U16, U24, U32};
use blake2::digest::{FixedOutput, KeyInit, Update, VariableOutput};
use blake2::{Blake2b, Blake2b512, Blake2bMac512, Blake2bVar, Blake2s256, Blake2sMac, Digest};

fn main() {
    let data = std::env::args().nth(1).unwrap_or_default();
    let data = data.as_bytes();
    let d1 = Blake2s256::digest(data);
    let d2 = Blake2b512::digest(data);
    let d3 = Blake2b::<U32>::digest(data);
    let mut m1 = Blake2sMac::<U16>::new_from_slice(b"0123456789abcdef").unwrap();
    Update::update(&mut m1, data);
    let t1 = m1.finalize_fixed();
    let mut m2 = Blake2sMac::<U24>::new_from_slice(b"0123456789abcdef").unwrap();
    Update::update(&mut m2, data);
    let t2 = m2.finalize_fixed();
    let mut m3 = Blake2bMac512::new_from_slice(b"0123456789abcdef").unwrap();
    blake2::digest::Mac::update(&mut m3, data);
    let t3 = blake2::digest::Mac::finalize(m3).into_bytes();
    let mut h = hmac::SimpleHmac::<Blake2s256>::new_from_slice(b"key").unwrap();
    Update::update(&mut h, data);
    let t4 = h.finalize_fixed();
    let mut var = Blake2bVar::new(10).unwrap();
    Update::update(&mut var, data);
    let mut out = [0u8; 10];
    var.finalize_variable(&mut out).unwrap();
    println!(
        "{} {} {} {} {} {} {} {}",
        d1.len(), d2.len(), d3.len(), t1.len(), t2.len(), t3.len(), t4.len(), out.len()
    );
}
