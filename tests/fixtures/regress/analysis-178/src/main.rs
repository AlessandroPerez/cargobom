// The AEADs and block-cipher modes of the generation after 0.10 (aead 0.6, cipher 0.5 over
// hybrid-array): the same types as before (`AesGcm<Aes256, U12>`, `ChaChaPoly1305<ChaCha20,
// U12>`, `cbc::Encryptor<Aes128>`, `CtrCore<Aes256, ..>`), with cipher's traits renamed
// (`BlockModeEncrypt`, `BlockCipherEncrypt`) and chacha20's rounds a marker type.
use aes_gcm::aead::{Aead, AeadInOut, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{
    BlockCipherEncrypt, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, StreamCipher,
};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};

fn main() {
    let msg = std::env::args().nth(1).unwrap_or_default();
    let msg = msg.as_bytes();
    let key = [1u8; 32];
    let n12 = [2u8; 12];
    let n24 = [3u8; 24];
    let a = Aes256Gcm::new_from_slice(&key).unwrap();
    let c1 = a.encrypt(&n12.into(), msg).unwrap();
    let p1 = a.decrypt(&n12.into(), c1.as_ref()).unwrap();
    let b = Aes128Gcm::new_from_slice(&key[..16]).unwrap();
    let mut buf = msg.to_vec();
    b.encrypt_in_place(&n12.into(), b"aad", &mut buf).unwrap();
    let c = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let c2 = c.encrypt(&n12.into(), msg).unwrap();
    let x = XChaCha20Poly1305::new_from_slice(&key).unwrap();
    let c3 = x.encrypt(&n24.into(), msg).unwrap();
    let iv = [4u8; 16];
    let k16 = [5u8; 16];
    let c4 = cbc::Encryptor::<aes::Aes128>::new(&k16.into(), &iv.into())
        .encrypt_padded_vec::<Pkcs7>(msg);
    let p4 = cbc::Decryptor::<aes::Aes128>::new(&k16.into(), &iv.into())
        .decrypt_padded_vec::<Pkcs7>(&c4)
        .unwrap();
    let mut stream = ctr::Ctr128BE::<aes::Aes256>::new(&key.into(), &iv.into());
    let mut s = msg.to_vec();
    stream.apply_keystream(&mut s);
    let mut block = [6u8; 16].into();
    aes::Aes128::new(&k16.into()).encrypt_block(&mut block);
    println!(
        "{} {} {} {} {} {} {} {}",
        p1.len(), buf.len(), c2.len(), c3.len(), c4.len(), p4.len(), s.len(), block.len()
    );
}
