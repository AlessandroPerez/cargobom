// `&mut` borrows held in the standard library's containers (`Vec`, `Option`, `Box`, arrays,
// `vec![]`): the cases where following them must not claim too much. Each case is its own
// function, so that one container handed elsewhere does not change how the others are read.
// Each call says what can reach it.
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
type D = &'static Digest;
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn n(i: usize) -> usize { arg(i).len() }
fn lend(r: &mut D) { if n(5) > 0 { *r = &SHA384; } }
fn add<'a>(v: &mut Vec<&'a mut D>, r: &'a mut D) { v.push(r); }
fn pset(v: &mut Vec<&mut D>) { *v[0] = &SHA1; }
struct BH<'a> { b: Box<&'a mut D> }
fn bset(h: BH) { **h.b = &SHA384; }

// two pointers in one `Vec`: a write through one of them may be either
fn two(d: &[u8]) {
    let (mut a1, mut a2): (D, D) = (&SHA256, &SHA256);
    let mut v = Vec::new();
    v.push(&mut a1);
    v.push(&mut a2);
    *v[0] = &SHA512;
    let _ = digest(a1, d); // SHA-512 (+ may SHA-256)
    let _ = digest(a2, d); // SHA-256 (+ may SHA-512)
}
// a `Vec` lent to a function that adds a pointer: what it holds is not seen here
fn lent(d: &[u8]) {
    let (mut b1, mut b2): (D, D) = (&SHA256, &SHA256);
    let mut v = vec![&mut b1];
    add(&mut v, &mut b2);
    *v[0] = &SHA384;
    let _ = digest(b1, d); // SHA-384 (+ may SHA-256)
    let _ = digest(b2, d); // SHA-256 (+ may SHA-384)
}
// a held pointer re-pointed through a borrow of its slot
fn repoint(d: &[u8]) {
    let (mut c1, mut c2): (D, D) = (&SHA256, &SHA256);
    let mut v = vec![&mut c1];
    let s = &mut v[0];
    *s = &mut c2;
    *v[0] = &SHA512;
    let _ = digest(c1, d); // SHA-256 (+ may SHA-512)
    let _ = digest(c2, d); // SHA-512 (+ may SHA-256)
}
// the slots swapped by a method of the slice
fn swapped(d: &[u8]) {
    let (mut e1, mut e2): (D, D) = (&SHA256, &SHA256);
    let mut v = vec![&mut e1, &mut e2];
    v.swap(0, 1);
    *v[0] = &SHA384;
    let _ = digest(e1, d); // SHA-256 (+ may SHA-384)
    let _ = digest(e2, d); // SHA-384 (+ may SHA-256)
}
// the pointers handed to a closure
fn closure(d: &[u8]) {
    let mut f1: D = &SHA256;
    let v = vec![&mut f1];
    v.into_iter().for_each(|r| *r = &SHA512);
    let _ = digest(f1, d); // SHA-512 (+ may SHA-256)
}
// pushed on one branch or the other
fn branch(d: &[u8]) {
    let (mut g1, mut g2): (D, D) = (&SHA256, &SHA256);
    let mut v = Vec::new();
    if n(1) > 0 { v.push(&mut g1); } else { v.push(&mut g2); }
    if let Some(r) = v.pop() { *r = &SHA384; }
    let _ = digest(g1, d); // SHA-256, SHA-384
    let _ = digest(g2, d); // SHA-256, SHA-384
}
// taken out of an `Option` before the write
fn taken(d: &[u8]) {
    let mut h1: D = &SHA256;
    let mut o = None;
    let _ = o.insert(&mut h1);
    let t = o.take();
    if let Some(r) = t { *r = &SHA512; }
    let _ = digest(h1, d); // SHA-512 (+ may SHA-256)
}
// a box moved into a struct handed to a function
fn boxed(d: &[u8]) {
    let mut i1: D = &SHA256;
    bset(BH { b: Box::new(&mut i1) });
    let _ = digest(i1, d); // SHA-384 (+ may SHA-256)
}
// a `Vec` handed to a function that writes through it
fn handed(d: &[u8]) {
    let mut j1: D = &SHA256;
    let mut v = vec![&mut j1];
    pset(&mut v);
    let _ = digest(j1, d); // SHA-1 (+ may SHA-256)
}
// `get_or_insert` on a value already there: either pointer
fn either(d: &[u8]) {
    let (mut k1, mut k2): (D, D) = (&SHA256, &SHA256);
    let mut o = Some(&mut k1);
    let r = o.get_or_insert(&mut k2);
    **r = &SHA512;
    let _ = digest(k1, d); // SHA-512 (+ may SHA-256)
    let _ = digest(k2, d); // SHA-256 (+ may SHA-512)
}
// a literal of two, iterated: each may be written or not
fn listed(d: &[u8]) {
    let (mut m1, mut m2): (D, D) = (&SHA256, &SHA256);
    for r in vec![&mut m1, &mut m2] { *r = &SHA384; }
    let _ = digest(m1, d); // SHA-384 (+ may SHA-256)
    let _ = digest(m2, d); // SHA-384 (+ may SHA-256)
}
// an array read at a constant index: that element only
fn indexed(d: &[u8]) {
    let (mut p1, mut p2): (D, D) = (&SHA256, &SHA256);
    let a = [&mut p1, &mut p2];
    *a[1] = &SHA512;
    let _ = digest(p1, d); // SHA-256
    let _ = digest(p2, d); // SHA-512
}
// two containers: a write through one does not reach the other's
fn apart(d: &[u8]) {
    let (mut q1, mut q2): (D, D) = (&SHA256, &SHA256);
    let mut v1 = Vec::new();
    v1.push(&mut q1);
    let mut v2 = Vec::new();
    v2.push(&mut q2);
    *v1[0] = &SHA1;
    let _ = v2.len();
    let _ = digest(q1, d); // SHA-1
    let _ = digest(q2, d); // SHA-256
}
// taken out and lent to a function that may write it
fn passed(d: &[u8]) {
    let mut r1: D = &SHA256;
    let mut v = Vec::new();
    v.push(&mut r1);
    lend(v.pop().unwrap());
    let _ = digest(r1, d); // SHA-256, SHA-384
}
// `replace` hands back what was there: the old pointer or, as far as the types tell, the new
fn replaced(d: &[u8]) {
    let (mut s1, mut s2): (D, D) = (&SHA256, &SHA256);
    let mut o = Some(&mut s1);
    let old = o.replace(&mut s2);
    if let Some(r) = old { *r = &SHA384; }
    let _ = o.is_some();
    let _ = digest(s1, d); // SHA-384 (+ may SHA-256)
    let _ = digest(s2, d); // SHA-256 (+ may SHA-384)
}
// a pointer into a borrowed `Option` the standard library hands out: not followed
fn inside(d: &[u8]) {
    let mut t: Option<D> = Some(&SHA256);
    let o: Option<&mut D> = Option::from(&mut t);
    if let Some(r) = o { *r = &SHA384; }
    let _ = digest(t.unwrap(), d); // SHA-384 (+ may SHA-256)
}

fn main() {
    let d = arg(0).into_bytes();
    two(&d); lent(&d); repoint(&d); swapped(&d); closure(&d); branch(&d); taken(&d);
    boxed(&d); handed(&d); either(&d); listed(&d); indexed(&d); apart(&d); passed(&d);
    replaced(&d); inside(&d);
}
