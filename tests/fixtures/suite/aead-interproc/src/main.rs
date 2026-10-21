use chacha20poly1305::aead::{Aead, KeyInit, Nonce};
use chacha20poly1305::XChaCha20Poly1305;

fn make_cipher() -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(&[8u8; 32].into())
}

fn protect<C: Aead>(cipher: &C, msg: &[u8]) -> Vec<u8> {
    let nonce = Nonce::<C>::default();
    seal(cipher, &nonce, msg)
}

fn seal<C: Aead>(cipher: &C, nonce: &Nonce<C>, msg: &[u8]) -> Vec<u8> {
    cipher.encrypt(nonce, msg).unwrap()
}

fn unprotect<C: Aead>(cipher: &C, ct: &[u8]) -> Vec<u8> {
    cipher.decrypt(&Nonce::<C>::default(), ct).unwrap()
}

fn main() {
    let cipher = make_cipher();
    let ct = protect(&cipher, b"interprocedural");
    let pt = unprotect(&cipher, &ct);
    println!("{} {}", ct.len(), pt.len());
}
