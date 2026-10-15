// audit 12 probe w2: local functions returning values that hold a borrow; parameter pointers stored into existing aggregates
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
type D = &'static Digest;
fn guard(x: &mut D) -> (&mut D, u8) { (x, 0) }
struct S { a: D, b: D }
impl S { fn slots(&mut self) -> (&mut D, &mut D) { (&mut self.a, &mut self.b) } }
fn iter_of(v: &mut Vec<D>) -> std::slice::IterMut<'_, D> { v.iter_mut() }
fn first(v: &mut Vec<D>) -> Option<&mut D> { v.first_mut() }
struct Holder<'a> { r: &'a mut D }
impl<'a> Holder<'a> { fn new(r: &'a mut D) -> Self { Holder { r } } }
fn arr_copy(slot: &mut D, other: &mut D) { let mut arr = [other]; arr[0] = slot; *arr[0] = &SHA512; }
fn tuple_assign(slot: &mut D, other: &mut D) { let mut t = (other, 0u8); t.0 = slot; *t.0 = &SHA384; }

fn main() {
    let d = arg(0).into_bytes();
    let mut x1: D = &SHA256;
    let (r, _) = guard(&mut x1);
    *r = &SHA512;
    let _ = digest(x1, &d);
    let mut s = S { a: &SHA256, b: &SHA1 };
    let (p, _q) = s.slots();
    *p = &SHA384;
    let _ = digest(s.a, &d);
    let mut v: Vec<D> = vec![&SHA256];
    for e in iter_of(&mut v) { *e = &SHA512; }
    let _ = digest(v[0], &d);
    let mut w: Vec<D> = vec![&SHA256];
    if let Some(f) = first(&mut w) { *f = &SHA384; }
    let _ = digest(w[0], &d);
    let mut x2: D = &SHA256;
    let h = Holder::new(&mut x2);
    *h.r = &SHA512;
    let _ = digest(x2, &d);
    let (mut x3, mut y3): (D, D) = (&SHA256, &SHA1);
    arr_copy(&mut x3, &mut y3);
    let _ = digest(x3, &d);
    let (mut x4, mut y4): (D, D) = (&SHA256, &SHA1);
    tuple_assign(&mut x4, &mut y4);
    let _ = digest(x4, &d);
}
