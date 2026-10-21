// round 11 regress (audit 10 probe w1): writes through `&mut` by trait methods and functions, variations
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

struct A { alg: &'static Digest }
struct B { alg: &'static Digest }
trait Up { fn up(&mut self); }
impl Up for A { fn up(&mut self) { self.alg = &SHA512; } }
impl Up for B { fn up(&mut self) {} }
fn gen_up<T: Up>(t: &mut T) { t.up() }

trait Slot {
    fn slot(&mut self) -> &mut &'static Digest;
    fn upgrade(&mut self) { *self.slot() = &SHA384; }
}
impl Slot for A { fn slot(&mut self) -> &mut &'static Digest { &mut self.alg } }

trait Base { fn set(&mut self, a: &'static Digest); }
trait Ext: Base { fn up2(&mut self) { self.set(&SHA384) } }
impl Base for A { fn set(&mut self, a: &'static Digest) { self.alg = a; } }
impl Base for B { fn set(&mut self, _a: &'static Digest) { self.alg = &SHA1; } }
impl Ext for A {}
impl Ext for B {}

fn alias(slot: &mut &'static Digest, other: &mut &'static Digest, c: bool) {
    let s = if c { slot } else { other };
    *s = &SHA512;
}
fn shadow(slot: &mut &'static Digest, other: &mut &'static Digest) {
    let mut s = slot;
    if arg(7).is_empty() { s = other; }
    *s = &SHA512;
}
fn swapper<'a>(mut slot: &'a mut &'static Digest, mut other: &'a mut &'static Digest) {
    std::mem::swap(&mut slot, &mut other);
    *slot = &SHA512;
}
fn even(slot: &mut &'static Digest, n: u32) { if n > 0 { odd(slot, n - 1) } else { *slot = &SHA384 } }
fn odd(slot: &mut &'static Digest, n: u32) { if n > 0 { even(slot, n - 1) } else { *slot = &SHA512 } }
struct W<'a> { slot: &'a mut &'static Digest }
fn wset(w: W) { *w.slot = &SHA512; }
fn opt_as_mut(mut o: Option<&mut &'static Digest>) { if let Some(s) = o.as_mut() { **s = &SHA384; } }

fn main() {
    let d = arg(0).into_bytes();
    // generic fn, the instance's impl does not write
    let mut b1 = B { alg: &SHA256 };
    gen_up(&mut b1);
    let _ = digest(b1.alg, &d); // SHA-256
    let mut a1 = A { alg: &SHA256 };
    gen_up(&mut a1);
    let _ = digest(a1.alg, &d); // SHA-512
    // dyn, the object's type does not write; A is coerced too
    let mut b2 = B { alg: &SHA384 };
    { let u: &mut dyn Up = &mut b2; u.up(); }
    let _ = digest(b2.alg, &d); // SHA-384
    let mut a2 = A { alg: &SHA256 };
    { let u: &mut dyn Up = &mut a2; u.up(); }
    let _ = digest(a2.alg, &d); // SHA-512
    // a default body writing through another trait method
    let mut a3 = A { alg: &SHA256 };
    a3.upgrade();
    let _ = digest(a3.alg, &d); // SHA-384
    // a supertrait's method called from a default body
    let mut a4 = A { alg: &SHA256 };
    a4.up2();
    let _ = digest(a4.alg, &d); // SHA-384
    let mut b4 = B { alg: &SHA256 };
    b4.up2();
    let _ = digest(b4.alg, &d); // SHA-1
    // a `&mut` chosen among parameters
    let mut x5: &'static Digest = &SHA256;
    let mut y5: &'static Digest = &SHA384;
    alias(&mut x5, &mut y5, arg(5).is_empty());
    let _ = digest(x5, &d); // SHA-256, SHA-512
    let _ = digest(y5, &d); // SHA-384, SHA-512
    // a parameter moved into a local that is then pointed elsewhere
    let mut x6: &'static Digest = &SHA256;
    let mut y6: &'static Digest = &SHA384;
    shadow(&mut x6, &mut y6);
    let _ = digest(x6, &d); // SHA-256, SHA-512
    let _ = digest(y6, &d); // SHA-384, SHA-512
    // parameters swapped
    let mut x7: &'static Digest = &SHA256;
    let mut y7: &'static Digest = &SHA384;
    swapper(&mut x7, &mut y7);
    let _ = digest(x7, &d); // SHA-256
    let _ = digest(y7, &d); // SHA-512
    // mutual recursion
    let mut x8: &'static Digest = &SHA256;
    even(&mut x8, arg(8).len() as u32);
    let _ = digest(x8, &d); // SHA-384, SHA-512
    // a struct holding the `&mut`
    let mut x9: &'static Digest = &SHA256;
    wset(W { slot: &mut x9 });
    let _ = digest(x9, &d); // SHA-512
    // `Option<&mut>` through `as_mut`
    let mut x10: &'static Digest = &SHA256;
    opt_as_mut(Some(&mut x10));
    let _ = digest(x10, &d); // SHA-384
    // a closure writing a capture, run by an iterator
    let mut x11: &'static Digest = &SHA256;
    (0..arg(11).len()).for_each(|_| x11 = &SHA512);
    let _ = digest(x11, &d); // SHA-256, SHA-512
    // a closure writing a capture, run by the program's generic function
    let mut x12: &'static Digest = &SHA256;
    run(|| x12 = &SHA384);
    let _ = digest(x12, &d); // SHA-384
}
fn run<F: FnMut()>(mut f: F) { f() }
