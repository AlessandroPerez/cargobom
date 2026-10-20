// Values holding `&mut` that the program's functions return (a struct, a tuple, an `Option`),
// written through by the caller or handed on: the cases where following them must not claim too
// much. Each call says what can reach it.
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
type D = &'static Digest;
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn n(i: usize) -> usize { arg(i).len() }

struct W<'a> { slot: &'a mut D }
fn wrap(x: &mut D) -> W<'_> { W { slot: x } }
fn pick<'a>(a: &'a mut D, b: &'a mut D) -> W<'a> { if n(1) > 0 { W { slot: a } } else { W { slot: b } } }
fn maybe(x: &mut D) -> Option<&mut D> { if n(2) > 0 { Some(x) } else { None } }
fn both<'a>(a: &'a mut D, b: &'a mut D) -> (&'a mut D, &'a mut D) { (b, a) }
fn written(x: &mut D) -> W<'_> { *x = &SHA384; W { slot: x } }
fn leaked() -> W<'static> { W { slot: Box::leak(Box::new(&SHA1 as D)) } }
fn gset<T: AsMut<D>>(mut t: T) { *t.as_mut() = &SHA512; }
impl AsMut<D> for W<'_> { fn as_mut(&mut self) -> &mut D { self.slot } }
struct S { alg: D, other: D }
trait Holds { fn holder(&mut self) -> W<'_>; }
impl Holds for S { fn holder(&mut self) -> W<'_> { W { slot: &mut self.alg } } }
fn holds_dyn(h: &mut dyn Holds) -> W<'_> { h.holder() }

fn main() {
    let d = arg(0).into_bytes();
    // either parameter, by a branch in the function: either may be written
    let (mut a1, mut a2): (D, D) = (&SHA256, &SHA256);
    let w = pick(&mut a1, &mut a2);
    *w.slot = &SHA512;
    let _ = digest(a1, &d); // SHA-256, SHA-512
    let _ = digest(a2, &d); // SHA-256, SHA-512
    // `Some` on one way only
    let mut b1: D = &SHA256;
    if let Some(r) = maybe(&mut b1) { *r = &SHA384; }
    let _ = digest(b1, &d); // SHA-256, SHA-384
    // a tuple of both, swapped
    let (mut c1, mut c2): (D, D) = (&SHA256, &SHA256);
    let (p, q) = both(&mut c1, &mut c2);
    *p = &SHA1;
    *q = &SHA512;
    let _ = digest(c1, &d); // SHA-512
    let _ = digest(c2, &d); // SHA-1
    // written by the function, then through what it returns
    let mut e1: D = &SHA256;
    let w = written(&mut e1);
    let _ = w.slot.output_len();
    let _ = digest(e1, &d); // SHA-384
    let mut e2: D = &SHA256;
    let w = written(&mut e2);
    *w.slot = &SHA512;
    let _ = digest(e2, &d); // SHA-512
    // its field pointed elsewhere by the caller first
    let (mut f1, mut f2): (D, D) = (&SHA256, &SHA256);
    let mut w = wrap(&mut f1);
    w.slot = &mut f2;
    *w.slot = &SHA384;
    let _ = digest(f1, &d); // SHA-256 (+ may SHA-384)
    let _ = digest(f2, &d); // SHA-384 (+ may SHA-256)
    // handed to a generic function
    let mut g1: D = &SHA256;
    gset(wrap(&mut g1));
    let _ = digest(g1, &d); // SHA-512 (+ may SHA-256)
    // kept in a `Vec`, written through later
    let mut h1: D = &SHA256;
    let mut v = vec![wrap(&mut h1)];
    *v[0].slot = &SHA1;
    drop(v);
    let _ = digest(h1, &d); // SHA-1 (+ may SHA-256)
    // called through a function pointer
    let mut i1: D = &SHA256;
    let fp: fn(&mut D) -> W<'_> = wrap;
    let w = fp(&mut i1);
    *w.slot = &SHA384;
    let _ = digest(i1, &d); // SHA-384 (+ may SHA-256)
    // a trait's method, through a trait object
    let mut s = S { alg: &SHA256, other: &SHA1 };
    let w = holds_dyn(&mut s);
    *w.slot = &SHA512;
    let _ = digest(s.alg, &d); // SHA-512 (+ may SHA-256)
    let _ = digest(s.other, &d); // SHA-1
    // a pointer the function makes itself: none of the caller's
    let mut j1: D = &SHA256;
    let w = leaked();
    *w.slot = &SHA384;
    let _ = digest(j1, &d); // SHA-256
    j1 = &SHA512;
    let _ = digest(j1, &d); // SHA-512
}
