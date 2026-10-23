// a closure of a library's generic function, cited where it is written: the closure's site,
// which the scan of the library's generic code records, is named without the instance's
// arguments, its instance with them elided (`f::<..>`, a path over 60 characters), as rcgen's
// in `serialize_der_with_signer`
use sha2::{Digest, Sha224};

fn with_writer<F: FnOnce(&mut Vec<u8>)>(f: F) -> Vec<u8> {
    let mut v = Vec::new();
    f(&mut v);
    v
}

pub fn serialize_with_a_writer_whose_name_is_long_enough<K: AsRef<[u8]>>(k: &K) -> Vec<u8> {
    with_writer(|writer| {
        writer.extend(Sha224::digest(k.as_ref()));
    })
}
