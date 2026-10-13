use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, CHACHA20_POLY1305};
use std::collections::HashMap;

fn nonce() -> Nonce {
    Nonce::assume_unique_for_key([2u8; 12])
}

fn main() {
    let mut keys: HashMap<&str, LessSafeKey> = HashMap::new();
    keys.insert("archive", LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &[1u8; 32]).unwrap()));
    keys.insert("stream", LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &[2u8; 32]).unwrap()));

    let mut live = b"live frame".to_vec();
    keys["stream"].seal_in_place_append_tag(nonce(), Aad::empty(), &mut live).unwrap();
    let n = keys["stream"].open_in_place(nonce(), Aad::empty(), &mut live).unwrap().len();

    let mut old = b"old record".to_vec();
    keys["archive"].seal_in_place_append_tag(nonce(), Aad::empty(), &mut old).unwrap();
    println!("{} {}", n, old.len());
}
