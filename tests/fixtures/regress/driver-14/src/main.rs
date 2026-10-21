// Constants and callees (second audit round): associated consts, consts a `const fn` computes,
// constants of generic instances, functions held in places.
use ring::digest::{self, Algorithm, Digest, SHA256, SHA384, SHA512, digest};

// K1: a trait with an algorithm per impl; the impl's method names `Self::ALG`, a free function
// names it through the type: both resolve to the impl's const, which names SHA-384
trait Scheme {
    const ALG: &'static Algorithm;
    fn hash(d: &[u8]) -> usize;
}
struct S384;
impl Scheme for S384 {
    const ALG: &'static Algorithm = &SHA384;
    fn hash(d: &[u8]) -> usize {
        digest(Self::ALG, d).as_ref().len()
    }
}
fn k1(d: &[u8]) -> usize {
    S384::hash(d) + digest(S384::ALG, d).as_ref().len()
}

// K2: consts whose value a const fn computes, and an inline const block calling it
const fn pick() -> &'static Algorithm {
    &SHA512
}
const PICKED: &Algorithm = pick();
struct Suite {
    alg: &'static Algorithm,
}
const fn suite() -> Suite {
    Suite { alg: &SHA256 }
}
const SUITE: Suite = suite();
fn k2(d: &[u8]) -> usize {
    digest(PICKED, d).as_ref().len()
        + digest(SUITE.alg, d).as_ref().len()
        + digest(const { pick() }, d).as_ref().len()
}

// K3: verification in a generic function: the key's algorithm (an aws-lc-rs const) is named
// in the item's MIR, evaluated away in the instance the walk scans; and a monomorphic copy
fn k3<B: AsRef<[u8]>>(pk: B, msg: &[u8], sig: &[u8]) -> bool {
    let k = aws_lc_rs::signature::UnparsedPublicKey::new(
        &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
        pk,
    );
    k.verify(msg, sig).is_ok()
}
fn k3m(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let k = aws_lc_rs::signature::UnparsedPublicKey::new(
        &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
        pk,
    );
    k.verify(msg, sig).is_ok()
}

// F1: a closure calls a KB function item it captured
fn f1(d: &[u8]) -> usize {
    let f = digest;
    let g = |x: &[u8]| f(&SHA256, x).as_ref().len();
    g(d)
}

// F2: a KB function item in a struct field, and in a tuple, then called
struct Holder<F> {
    f: F,
}
fn f2(d: &[u8]) -> usize {
    let h = Holder { f: digest };
    let t = (digest, 1u8);
    (h.f)(&SHA384, d).as_ref().len() + (t.0)(&SHA512, d).as_ref().len() + t.1 as usize
}

// F3: a call through a local function pointer, whose result another call takes: the origin
// names the function the pointer holds
fn f3(d: &[u8]) -> usize {
    let h: fn(&'static Algorithm, &[u8]) -> Digest = digest::digest;
    let x = h(&SHA256, d);
    digest(&SHA384, x.as_ref()).as_ref().len()
}

fn main() {
    println!("{} {} {} {}", k1(b"a"), k2(b"b"), f1(b"c"), f2(b"d") + f3(b"e"));
    println!("{} {}", k3(b"pk", b"m", b"s"), k3m(b"pk", b"m", b"s"));
}
