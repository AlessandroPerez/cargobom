// a key the program's own helper is given: its provenance is what the helper's callers pass (a
// literal, the environment), each classified in its caller, beside the parameter itself
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

fn seal(key: &[u8], msg: &mut Vec<u8>) {
    let k = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).unwrap());
    let nonce = Nonce::assume_unique_for_key([0u8; 12]);
    k.seal_in_place_append_tag(nonce, Aad::empty(), msg).unwrap();
}

fn main() {
    let mut m = b"message".to_vec();
    seal(&[1u8; 32], &mut m);
    let env = std::env::var("SEAL_KEY").unwrap_or_default();
    seal(env.as_bytes(), &mut m);
    println!("{}", m.len());
}
