use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};

struct Settings {
    label: &'static str,
    cipher: &'static aead::Algorithm,
}

fn upgrade(s: &mut Settings) {
    s.cipher = &aead::AES_256_GCM;
}

fn key_for(s: &Settings) -> LessSafeKey {
    let bytes = vec![3u8; s.cipher.key_len()];
    LessSafeKey::new(UnboundKey::new(s.cipher, &bytes).unwrap())
}

fn encrypt(s: &Settings, msg: &[u8]) -> Vec<u8> {
    let mut buf = msg.to_vec();
    let nonce = Nonce::assume_unique_for_key([0u8; 12]);
    key_for(s).seal_in_place_append_tag(nonce, Aad::from(s.label), &mut buf).unwrap();
    buf
}

fn decrypt(s: &Settings, mut ct: Vec<u8>) -> usize {
    let nonce = Nonce::assume_unique_for_key([0u8; 12]);
    key_for(s).open_in_place(nonce, Aad::from(s.label), &mut ct).unwrap().len()
}

fn main() {
    let mut s = Settings { label: "v1", cipher: &aead::AES_128_GCM };
    upgrade(&mut s);
    let ct = encrypt(&s, b"field");
    println!("{}", decrypt(&s, ct));
}
