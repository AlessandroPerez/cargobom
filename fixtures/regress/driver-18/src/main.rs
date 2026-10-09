// Values the origin search and the links follow (fourth audit round): enum variants, statics
// written at run time, a generic function's associated constant, a local closure's parameter,
// a branch on a named constant, an algorithm only an unreachable caller passes, and a program
// static naming a composite descriptor.
#![allow(static_mut_refs)]
use ring::{digest, hmac};
use sha2::{Digest, Sha512_224, Sha512_256};
use std::sync::{LazyLock, OnceLock, RwLock};

enum Pick {
    A(&'static digest::Algorithm),
    B(&'static digest::Algorithm),
}

// a variant's payload is read only from that variant: 31 SHA-384, 32 SHA-1
fn picks() -> usize {
    let p = if std::env::args().count() > 1 {
        Pick::A(&digest::SHA384)
    } else {
        Pick::B(&digest::SHA1_FOR_LEGACY_USE_ONLY)
    };
    match p {
        Pick::A(x) => digest::digest(x, b"a").as_ref().len(),
        Pick::B(y) => digest::digest(y, b"b").as_ref().len(),
    }
}

// statics written at run time: what the program puts there, and their initial values
static ALG: RwLock<&'static digest::Algorithm> = RwLock::new(&digest::SHA256);
static mut ALG2: &'static digest::Algorithm = &digest::SHA512_256;
static ONCE: OnceLock<&'static digest::Algorithm> = OnceLock::new();
static LAZY: LazyLock<&'static digest::Algorithm> = LazyLock::new(|| &digest::SHA384);

fn statics() -> usize {
    *ALG.write().unwrap() = &digest::SHA1_FOR_LEGACY_USE_ONLY;
    // one of 2: SHA-256 (initial) or SHA-1
    let a = digest::digest(*ALG.read().unwrap(), b"x").as_ref().len();
    unsafe { ALG2 = &digest::SHA1_FOR_LEGACY_USE_ONLY };
    // one of 2: SHA-512/256 or SHA-1
    let b = digest::digest(unsafe { ALG2 }, b"y").as_ref().len();
    let _ = ONCE.set(&digest::SHA512);
    // SHA-512, SHA-384
    let c = digest::digest(ONCE.get().unwrap(), b"o").as_ref().len();
    let d = digest::digest(*LAZY, b"l").as_ref().len();
    a + b + c + d
}

// a trait's associated constant in generic code: the instance's (SHA-384), never the trait's
// default (SHA-256, present only); a closure capturing it (SHA-512)
trait Scheme {
    const ALG: &'static digest::Algorithm = &digest::SHA256;
}
struct S384;
impl Scheme for S384 {
    const ALG: &'static digest::Algorithm = &digest::SHA384;
}
trait Plain {
    const ALG: &'static digest::Algorithm;
}
struct P512;
impl Plain for P512 {
    const ALG: &'static digest::Algorithm = &digest::SHA512;
}
fn hash<T: Scheme>(d: &[u8]) -> usize {
    digest::digest(T::ALG, d).as_ref().len()
}
fn each<T: Plain>(items: &[&[u8]]) -> usize {
    let alg = T::ALG;
    items.iter().map(move |d| digest::digest(alg, d).as_ref().len()).sum()
}

// an enum-typed parameter (SHA-256), a local closure's parameter (SHA-512)
enum Mode {
    Hash(&'static digest::Algorithm),
    Skip,
}
fn run(m: Mode, d: &[u8]) -> usize {
    match m {
        Mode::Hash(a) => digest::digest(a, d).as_ref().len(),
        Mode::Skip => 0,
    }
}

// a branch on a named constant that is false: neither call runs
const FLAG: bool = false;
fn flagged() -> usize {
    Sha512_224::digest(b"helper").len()
}

// SHA-512 reaches `hash_with` only from `dead`, never called: present there; SHA-256 reachable
fn hash_with(alg: &'static digest::Algorithm, d: &[u8]) -> usize {
    digest::digest(alg, d).as_ref().len()
}
fn live(d: &[u8]) -> usize {
    hash_with(&digest::SHA256, d)
}
#[allow(dead_code)]
fn dead(d: &[u8]) -> usize {
    hash_with(&digest::SHA512, d)
}

// a program static naming a composite descriptor (HMAC-SHA-256, which names SHA-256): the
// calls are HMAC-SHA-256's, the key hard-coded
static MAC_ALG: &hmac::Algorithm = &hmac::HMAC_SHA256;
fn mac() -> usize {
    let key = hmac::Key::new(*MAC_ALG, b"hard-coded hmac key");
    hmac::sign(&key, b"m").as_ref().len()
}

fn main() {
    let mut n = picks() + statics() + hash::<S384>(b"h") + each::<P512>(&[b"e"]);
    n += run(Mode::Hash(&digest::SHA256), b"r") + run(Mode::Skip, b"s");
    let f = |a: &'static digest::Algorithm, d: &[u8]| digest::digest(a, d).as_ref().len();
    n += f(&digest::SHA512, b"c");
    if FLAG {
        n += Sha512_256::digest(b"flag").len() + flagged();
    }
    n += live(b"l") + mac();
    println!("{n}");
}
