// round 12 regress (audit 11 probe wr1): writes through `&mut dyn`, generic writes, borrows a method returns, copies of `&mut` parameters, swap/take/replace
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

struct A { alg: &'static Digest }
struct B { alg: &'static Digest }
trait Up { fn up(&mut self); }
impl Up for A { fn up(&mut self) { self.alg = &SHA512; } }
impl Up for B { fn up(&mut self) {} }
struct Outer { b: B }

fn up_dyn(u: &mut dyn Up) { u.up() }
fn up_gen<T: Up + ?Sized>(u: &mut T) { u.up() }

impl A { fn slot(&mut self) -> &mut &'static Digest { &mut self.alg } }
fn put(a: &mut A) { *a.slot() = &SHA384; }

fn pick_slot<'a>(x: &'a mut &'static Digest, y: &'a mut &'static Digest) -> &'a mut &'static Digest { if arg(3).is_empty() { x } else { y } }

fn tuple_copy(slot: &mut &'static Digest, other: &mut &'static Digest) {
    let (s, _o) = if arg(4).is_empty() { (slot, other) } else { (other, slot) };
    *s = &SHA512;
}
fn replace_ref<'a>(mut slot: &'a mut &'static Digest, other: &'a mut &'static Digest) {
    let _old = std::mem::replace(&mut slot, other);
    *slot = &SHA512;
}
fn take_val(slot: &mut &'static Digest) -> &'static Digest { std::mem::replace(slot, &SHA1) }

fn main() {
    let d = arg(0).into_bytes();
    let mut a0 = A { alg: &SHA256 };
    { let u: &mut dyn Up = &mut a0; u.up(); }
    let mut o = Outer { b: B { alg: &SHA384 } };
    { let u: &mut dyn Up = &mut o.b; u.up(); }
    let _ = digest(o.b.alg, &d);
    let mut bx = Box::new(B { alg: &SHA384 });
    { let u: &mut dyn Up = &mut *bx; u.up(); }
    let _ = digest(bx.alg, &d);
    let mut b1 = B { alg: &SHA384 };
    up_dyn(&mut b1);
    let _ = digest(b1.alg, &d);
    let mut b2 = B { alg: &SHA384 };
    { let u: &mut dyn Up = &mut b2; up_gen(u); }
    let _ = digest(b2.alg, &d);
    let mut a1 = A { alg: &SHA256 };
    let mut b3 = B { alg: &SHA384 };
    { let u: &mut dyn Up = if arg(1).is_empty() { &mut a1 } else { &mut b3 }; u.up(); }
    let _ = digest(a1.alg, &d);
    let _ = digest(b3.alg, &d);
    let mut a2 = A { alg: &SHA256 };
    put(&mut a2);
    let _ = digest(a2.alg, &d);
    let mut a3 = A { alg: &SHA256 };
    *a3.slot() = &SHA384;
    let _ = digest(a3.alg, &d);
    let mut x1: &'static Digest = &SHA256;
    let mut y1: &'static Digest = &SHA384;
    *pick_slot(&mut x1, &mut y1) = &SHA512;
    let _ = digest(x1, &d);
    let _ = digest(y1, &d);
    let mut x2: &'static Digest = &SHA256;
    let mut y2: &'static Digest = &SHA384;
    tuple_copy(&mut x2, &mut y2);
    let _ = digest(x2, &d);
    let _ = digest(y2, &d);
    let mut x3: &'static Digest = &SHA256;
    let mut y3: &'static Digest = &SHA384;
    replace_ref(&mut x3, &mut y3);
    let _ = digest(x3, &d);
    let _ = digest(y3, &d);
    let mut x4: &'static Digest = &SHA256;
    let t4 = take_val(&mut x4);
    let _ = digest(t4, &d);
    let _ = digest(x4, &d);
    let mut x5: &'static Digest = &SHA256;
    let mut y5: &'static Digest = &SHA384;
    std::mem::swap(&mut x5, &mut y5);
    let _ = digest(x5, &d);
    let mut x6: &'static Digest = &SHA256;
    let old6 = std::mem::replace(&mut x6, &SHA1);
    let _ = digest(old6, &d);
    let _ = digest(x6, &d);
}
