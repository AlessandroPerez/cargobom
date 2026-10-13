// Argument origins and constants (fifth audit round).
use std::io::{self, Write};

use aes_gcm::aead::KeyInit;
use aes_gcm::Aes256Gcm;
use rand::rngs::OsRng;
use rand::RngCore;
use ring::digest::{digest, Algorithm, SHA256, SHA384};
use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

// O1: random keys in a box, filled through `&mut *key`, a boxed slice and a reference to the
// contents: rng, not the zeros the box starts with
fn o1() -> usize {
    let mut key = Box::new([0u8; 32]);
    OsRng.fill_bytes(&mut *key);
    let mut key2: Box<[u8]> = vec![0u8; 32].into_boxed_slice();
    OsRng.fill_bytes(&mut key2);
    let mut key3 = Box::new([0u8; 32]);
    let r: &mut [u8; 32] = &mut key3;
    OsRng.fill_bytes(r);
    Aes256Gcm::new_from_slice(&*key).is_ok() as usize
        + Aes256Gcm::new_from_slice(&key2).is_ok() as usize
        + Aes256Gcm::new_from_slice(&*key3).is_ok() as usize
}

// O2: keys in secret wrappers are what was put there: hard-coded, environment, hard-coded
fn o2() -> usize {
    let k = Zeroizing::new([7u8; 32]);
    let e = Zeroizing::new(std::env::var("K").unwrap_or_default().into_bytes());
    let s: SecretBox<[u8; 32]> = SecretBox::new(Box::new([9u8; 32]));
    Aes256Gcm::new_from_slice(&*k).is_ok() as usize
        + Aes256Gcm::new_from_slice(&e).is_ok() as usize
        + Aes256Gcm::new_from_slice(s.expose_secret()).is_ok() as usize
}

// O3: an optional key falling back to the type's default: the parameter or a constant
fn o3(k: Option<[u8; 32]>) -> bool {
    Aes256Gcm::new_from_slice(&k.unwrap_or_default()).is_ok()
}

// O4: data hashed through the hasher's `io::Write` impl: two SHA-512 digest uses
fn o4(mut r: impl io::Read) -> io::Result<Vec<u8>> {
    let mut h = Sha512::new();
    io::copy(&mut r, &mut h)?;
    h.write_all(b"trailer")?;
    Ok(h.finalize().to_vec())
}

// O5: an associated const nothing uses that would panic if evaluated (zerocopy 0.7's
// `INTO_REF_INTO_MUT_ARE_SOUND`): rustc never evaluates it, nor may the driver; and one
// computed by a `const fn` choosing between two descriptors, which the driver may evaluate
trait Sound {
    const OK: bool;
}
struct Never;
impl Sound for Never {
    const OK: bool = panic!("not sound");
}
const fn choose(fast: bool) -> &'static Algorithm {
    if fast { &SHA256 } else { &SHA384 }
}
trait Scheme {
    const ALG: &'static Algorithm;
}
struct Picked;
impl Scheme for Picked {
    const ALG: &'static Algorithm = choose(false);
}
fn o5(d: &[u8]) -> usize {
    digest(Picked::ALG, d).as_ref().len()
}

fn main() {
    let o = if std::env::args().count() > 1 { Some([1u8; 32]) } else { None };
    let d = std::env::args().next().unwrap_or_default().into_bytes();
    println!("{} {} {} {:?} {}", o1(), o2(), o3(o), o4(&d[..]).map(|h| h.len()), o5(&d));
}
