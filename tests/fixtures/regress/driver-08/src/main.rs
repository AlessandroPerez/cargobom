use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use aws_lc_rs::digest;

// A1: aws-lc-rs descriptor (a const) passed by reference: promoted
fn a1(key: &[u8], msg: &mut Vec<u8>) {
    let k = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).unwrap());
    let nonce = Nonce::assume_unique_for_key([0u8; 12]);
    k.seal_in_place_append_tag(nonce, Aad::empty(), msg).unwrap();
}

// A2: an aws-lc-rs const used in a generic fn reached from main
fn a2<T: AsRef<[u8]>>(d: T) -> usize {
    digest::digest(&digest::SHA384, d.as_ref()).as_ref().len()
}

fn main() {
    let mut m = b"hello".to_vec();
    a1(&[1u8; 32], &mut m);
    println!("{}", a2(b"x"));
}
