// Round 6 audit probe p2: a hash named as a value and called through the pointer; unmodelled
// or newly modelled algorithms (BLAKE2b hash and MAC, Blowfish, Salsa20, P-256 ECDSA and ECDH),
// whose library internals must not repeat the operations the program's calls report.
use blake2::digest::Mac;
use blowfish::cipher::{BlockEncrypt, KeyInit};
use p256::ecdsa::signature::Signer;
use rand_core::OsRng;
use salsa20::cipher::{KeyIvInit, StreamCipher};
use sha2::Digest;

fn main() {
    // a modelled hash named as a value, called through the pointer
    let f = <sha2::Sha256 as Digest>::digest;
    let a = f(b"abc");
    // BLAKE2b (unmodelled): hash and keyed MAC
    let b = blake2::Blake2b512::digest(b"abc");
    let mut m = <blake2::Blake2bMac512 as Mac>::new_from_slice(b"key").unwrap();
    Mac::update(&mut m, b"abc");
    let t = m.finalize().into_bytes();
    // Blowfish (unmodelled) block encryption
    let bf = blowfish::Blowfish::<byteorder::BE>::new_from_slice(b"0123456789abcdef").unwrap();
    let mut blk = [0u8; 8].into();
    bf.encrypt_block(&mut blk);
    // Salsa20 (unmodelled) stream cipher
    let mut s = salsa20::Salsa20::new(&[1u8; 32].into(), &[2u8; 8].into());
    let mut buf = [0u8; 16];
    s.apply_keystream(&mut buf);
    // P-256 ECDSA (unmodelled): key generation, signing
    let sk = p256::ecdsa::SigningKey::random(&mut OsRng);
    let sig: p256::ecdsa::Signature = sk.sign(b"msg");
    // P-256 ECDH (unmodelled)
    let e = p256::ecdh::EphemeralSecret::random(&mut OsRng);
    let pk = p256::PublicKey::from(&e);
    let shared = e.diffie_hellman(&pk);
    println!("{:x} {:x} {:x} {:?} {:?} {:?} {:?}", a, b, t, blk, buf, sig, shared.raw_secret_bytes());
}
