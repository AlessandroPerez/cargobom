// audit 12 probe w1: writes through &mut: dyn with default bodies, aggregates, reborrows, returned borrows, old values
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
use std::cell::{Cell, RefCell};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
trait Up { fn up(&mut self) { self.set(&SHA512); } fn set(&mut self, a: &'static Digest); }
struct A { alg: &'static Digest }
impl Up for A { fn set(&mut self, a: &'static Digest) { self.alg = a; } }
struct B { alg: &'static Digest }
impl Up for B { fn up(&mut self) {} fn set(&mut self, _a: &'static Digest) {} }
fn up_dyn(u: &mut dyn Up) { u.up() }
fn up_two(u: &mut dyn Up) { up_dyn(u) }
struct Pair<'a> { a: &'a mut &'static Digest, b: &'a mut &'static Digest }
fn field_copy(slot: &mut &'static Digest, other: &mut &'static Digest) { let mut p = Pair { a: other, b: &mut &SHA1 }; p.a = slot; *p.a = &SHA384; let _ = p.b; }
fn reborrow_tuple(slot: &mut &'static Digest, other: &mut &'static Digest) { let s: &mut &'static Digest = &mut *slot; let (x, _y) = if arg(1).len() > 1 { (s, other) } else { (other, s) }; *x = &SHA512; }
fn opt_copy(slot: &mut &'static Digest) { let o = Some(slot); if let Some(s) = o { *s = &SHA384; } }
fn ident(slot: &mut &'static Digest) { let s = std::convert::identity(slot); *s = &SHA512; }
fn swap_in(slot: &mut &'static Digest) { let mut l: &'static Digest = &SHA384; std::mem::swap(slot, &mut l); }
struct W<'a> { r: &'a mut &'static Digest }
fn wrap<'a>(x: &'a mut &'static Digest) -> W<'a> { W { r: x } }
fn opt_mut<'a>(x: &'a mut &'static Digest) -> Option<&'a mut &'static Digest> { Some(x) }
struct S { alg: &'static Digest, other: &'static Digest }
impl S { fn slot(&mut self) -> &mut &'static Digest { &mut self.alg } }
fn slot_of(s: &mut S) -> &mut &'static Digest { &mut s.alg }

fn main() {
    let d = arg(0).into_bytes();
    let mut a1 = A { alg: &SHA256 };
    up_dyn(&mut a1);
    let _ = digest(a1.alg, &d);
    let mut b1 = B { alg: &SHA384 };
    up_two(&mut b1);
    let _ = digest(b1.alg, &d);
    let mut a2 = A { alg: &SHA256 };
    up_two(&mut a2);
    let _ = digest(a2.alg, &d);
    let (mut x1, mut y1): (&'static Digest, &'static Digest) = (&SHA256, &SHA1);
    field_copy(&mut x1, &mut y1);
    let _ = digest(x1, &d);
    let _ = digest(y1, &d);
    let (mut x2, mut y2): (&'static Digest, &'static Digest) = (&SHA256, &SHA1);
    reborrow_tuple(&mut x2, &mut y2);
    let _ = digest(x2, &d);
    let _ = digest(y2, &d);
    let mut x3: &'static Digest = &SHA256;
    opt_copy(&mut x3);
    let _ = digest(x3, &d);
    let mut x4: &'static Digest = &SHA256;
    ident(&mut x4);
    let _ = digest(x4, &d);
    let mut x5: &'static Digest = &SHA256;
    swap_in(&mut x5);
    let _ = digest(x5, &d);
    let mut x6: &'static Digest = &SHA256;
    let w = wrap(&mut x6);
    *w.r = &SHA512;
    let _ = digest(x6, &d);
    let mut x7: &'static Digest = &SHA256;
    if let Some(r) = opt_mut(&mut x7) { *r = &SHA384; }
    let _ = digest(x7, &d);
    let mut s1 = S { alg: &SHA256, other: &SHA1 };
    let r = s1.slot();
    *r = &SHA512;
    let _ = digest(s1.alg, &d);
    let _ = digest(s1.other, &d);
    let mut s2 = S { alg: &SHA256, other: &SHA1 };
    *slot_of(&mut s2) = &SHA384;
    let _ = digest(s2.alg, &d);
    let mut x8: &'static Digest = &SHA256;
    let old = std::mem::replace(&mut x8, &SHA1);
    let _ = digest(old, &d);
    let _ = digest(x8, &d);
    let c = Cell::new(&SHA256);
    let oldc = c.replace(&SHA1);
    let _ = digest(oldc, &d);
    let rc = RefCell::new(&SHA384);
    let oldr = rc.replace(&SHA1);
    let _ = digest(oldr, &d);
    let mut o: Option<&'static Digest> = Some(&SHA512);
    let t = o.take().unwrap_or(&SHA384);
    let _ = digest(t, &d);
    let mut o2: Option<&'static Digest> = None;
    let t2 = o2.replace(&SHA1).unwrap_or(&SHA256);
    let _ = digest(t2, &d);
    let _ = digest(o2.unwrap_or(&SHA384), &d);
    let mut o3: Option<&'static Digest> = Some(&SHA256);
    let t3 = o3.insert(&SHA512);
    let _ = digest(*t3, &d);
}
