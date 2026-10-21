// functions and closures run through pointers and trait objects: each run reaches its call, or
// the call says the values are not all followed
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
type H = fn(&'static Digest);
fn h1(a: &'static Digest) { let _ = digest(a, b"h1"); } // SHA-256, SHA-1
fn h2(a: &'static Digest) { let _ = digest(a, b"h2"); } // SHA-256, SHA-1
fn h3(a: &'static Digest) { let _ = digest(a, b"h3"); } // SHA-256, SHA-1
fn h4(a: &'static Digest) { let _ = digest(a, b"h4"); } // SHA-256, SHA-1
fn h5(a: &'static Digest) { let _ = digest(a, b"h5"); } // SHA-384, SHA-1
fn h6(a: &'static Digest) { let _ = digest(a, b"h6"); } // SHA-256, SHA-1
fn h7(a: &'static Digest) { let _ = digest(a, b"h7"); } // SHA-256, SHA-1
fn h8(a: &'static Digest) { let _ = digest(a, b"h8"); } // SHA-256, SHA-1
fn h9(a: &'static Digest) { let _ = digest(a, b"h9"); } // SHA-256, SHA-1
fn h10(a: &'static Digest) { let _ = digest(a, b"h10"); } // SHA-256, SHA-1
fn h11(a: &'static Digest) { let _ = digest(a, b"h11"); } // SHA-256, SHA-1
fn h12(a: &'static Digest) { let _ = digest(a, b"h12"); } // SHA-384, SHA-512 (the standard library runs it)
fn h13(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); } // SHA-512: no pointer of its type is called
fn h14(a: &'static Digest) { let _ = digest(a, b"h14"); } // SHA-256, SHA-1
fn h15(a: &'static Digest) { let _ = digest(a, b"h15"); } // SHA-256, SHA-1
fn h16(a: &'static Digest) { let _ = digest(a, b"h16"); } // SHA-256, SHA-1
fn h17(a: &'static Digest) { let _ = digest(a, b"h17"); } // SHA-384, SHA-512 (`map` runs the pointer)
fn h18(a: &'static Digest) { let _ = digest(a, b"h18"); } // SHA-384, SHA-512
fn h19(a: &'static Digest) { let _ = digest(a, b"h19"); } // SHA-256, SHA-1
static D14: &(dyn Fn(&'static Digest) + Sync) = &h14;
static P15: H = h15;
static T16: [H; 1] = [h16];
trait Handler: Fn(&'static Digest) {}
impl<F: Fn(&'static Digest)> Handler for F {}
trait Alg { fn run(&self, a: &'static Digest); }
struct X;
impl Alg for X { fn run(&self, a: &'static Digest) { let _ = digest(a, b"x"); } } // SHA-256, SHA-1 (SHA-512 possible: `W<u8>` is coerced to `dyn Alg` too)
struct W<T>(T);
impl<T: Copy> Alg for W<T> { fn run(&self, a: &'static Digest) { let _ = digest(a, b"w"); } } // SHA-384, SHA-512
// a generic trait: a call on `dyn G<A1>` runs no body of `G<A2>`
trait G<T> { fn g(&self, a: T); }
struct A1(&'static Digest);
struct A2(&'static Digest);
struct GA;
struct GB;
impl G<A1> for GA { fn g(&self, a: A1) { let _ = digest(a.0, b"ga"); } } // SHA-256, SHA-1
impl G<A2> for GB { fn g(&self, a: A2) { let _ = digest(a.0, b"gb"); } } // SHA-384, SHA-512
fn run(fs: &[&dyn Fn(&'static Digest)]) { for f in fs { f(&SHA1); } }
fn run2(fs: &[H]) { for f in fs { f(&SHA1); } }
fn runb(b: Box<dyn Fn(&'static Digest)>) { b(&SHA1) }
struct P { f: H }
fn runp(p: &P) { (p.f)(&SHA1) }
fn rund(f: &dyn Fn(&'static Digest)) { f(&SHA1) }
fn runh(f: &dyn Handler) { f(&SHA1) }
fn gen<F: Fn(&'static Digest)>(f: Rc<F>) { f(&SHA1) }
fn main() {
    // an Rc of a closure made a trait object: SHA-256, SHA-1
    let c = |a: &'static Digest| { let _ = digest(a, b"1"); };
    c(&SHA256);
    let r: Rc<dyn Fn(&'static Digest)> = Rc::new(c);
    r(&SHA1);
    // an Arc: SHA-384, SHA-512
    let k = |a: &'static Digest| { let _ = digest(a, b"2"); };
    k(&SHA384);
    let s: Arc<dyn Fn(&'static Digest) + Send + Sync> = Arc::new(k);
    s(&SHA512);
    // a pinned box: SHA-384, SHA-512
    let q = |a: &'static Digest| { let _ = digest(a, b"3"); };
    q(&SHA384);
    let p: Pin<Box<dyn Fn(&'static Digest)>> = Box::pin(q);
    p(&SHA512);
    // a closure handed in a slice of trait objects: SHA-384, SHA-1
    let m = |a: &'static Digest| { let _ = digest(a, b"4"); };
    m(&SHA384);
    run(&[&m]);
    // an Rc of a closure, cloned and called (no trait object): SHA-512, SHA-256
    let n = |a: &'static Digest| { let _ = digest(a, b"5"); };
    let rn = Rc::new(n);
    rn(&SHA512);
    let rn2 = rn.clone();
    rn2(&SHA256);
    h1(&SHA256); let r1: Rc<dyn Fn(&'static Digest)> = Rc::new(h1); r1(&SHA1);
    h2(&SHA256); let a2: Arc<dyn Fn(&'static Digest)> = Arc::new(h2); a2(&SHA1);
    h3(&SHA256); let b3: Box<dyn Fn(&'static Digest)> = Box::new(h3); b3(&SHA1);
    h4(&SHA256); run(&[&h4]);
    h5(&SHA384); gen(Rc::new(h5));
    h6(&SHA256); run2(&[h6]);
    h7(&SHA256); runb(Box::new(h7));
    h8(&SHA256); runp(&P { f: h8 });
    h9(&SHA256); let v: Vec<H> = vec![h9]; for f in &v { f(&SHA1); }
    h10(&SHA256); rund(&h10);
    h11(&SHA256); let o: Option<H> = Some(h11); if let Some(f) = o { f(&SHA1) }
    // a pointer handed to the standard library, which calls it: SHA-384, SHA-512
    h12(&SHA384); let p12: H = h12; [&SHA512].into_iter().for_each(p12);
    h14(&SHA256); D14(&SHA1);
    h15(&SHA256); P15(&SHA1);
    h16(&SHA256); T16[0](&SHA1);
    h17(&SHA384); let p17: H = h17; let _ = Some(&SHA512).map(p17);
    h18(&SHA384); let _ = Some(&SHA512).map(h18);
    h19(&SHA256); runh(&h19);
    X.run(&SHA256); let t: &dyn Alg = &X; t.run(&SHA1);
    let w = W(1u8); w.run(&SHA384); let tw: &dyn Alg = &w; tw.run(&SHA512);
    GA.g(A1(&SHA256)); let ga: &dyn G<A1> = &GA; ga.g(A1(&SHA1));
    GB.g(A2(&SHA384)); let gb: &dyn G<A2> = &GB; gb.g(A2(&SHA512));
    h13(&SHA512, b"13"); let _p13: fn(&'static Digest, &[u8]) = h13;
}
