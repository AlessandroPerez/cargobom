// a pointer whose own place is borrowed by `&mut`: written through after the loan, it is followed
// when the loan cannot change it (only read through, `f(&mut s)` coerced to `f(&mut *s)`; a
// closure of edition 2015 writing through it), not when it can (handed on, swapped, written
// through). Each case is its own function.
extern crate ring;
use ring::digest::{digest, Algorithm as Digest, SHA256, SHA384, SHA512};
type D = &'static Digest;
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn n(i: usize) -> usize { arg(i).len() }
fn lend(r: &mut D) { if n(5) > 0 { *r = &SHA384; } }
fn repoint<'a>(s: &mut &'a mut D, to: &'a mut D) { if n(7) > 0 { *s = to; } }

// `lend(&mut s)` hands on `&mut *s`: `s` still points to `a`
fn coerced(d: &[u8]) {
    let mut a: D = &SHA256;
    let mut s: &mut D = &mut a;
    lend(&mut s);
    *s = &SHA512;
    let _ = digest(a, d); // SHA-512
}
// a closure writing through `s` borrows `s` itself (edition 2015), but cannot change it
fn captured(d: &[u8]) {
    let mut b: D = &SHA256;
    let s: &mut D = &mut b;
    {
        let mut c = || { if n(6) > 0 { *s = &SHA384; } };
        c();
    }
    *s = &SHA512;
    let _ = digest(b, d); // SHA-512
}
// handed on (`&mut &mut D`): where it points after is not followed
fn handed(d: &[u8]) {
    let (mut c1, mut c2): (D, D) = (&SHA256, &SHA256);
    {
        let mut s: &mut D = &mut c1;
        repoint(&mut s, &mut c2);
        *s = &SHA512;
    }
    let _ = digest(c1, d); // SHA-512 or SHA-256
    let _ = digest(c2, d); // SHA-512 or SHA-256
}
// swapped with another pointer
fn swapped(d: &[u8]) {
    let (mut e1, mut e2): (D, D) = (&SHA256, &SHA256);
    {
        let mut s: &mut D = &mut e1;
        let mut t: &mut D = &mut e2;
        if n(8) > 0 { std::mem::swap(&mut s, &mut t); }
        *s = &SHA384;
        let _ = t;
    }
    let _ = digest(e1, d); // SHA-384 or SHA-256
    let _ = digest(e2, d); // SHA-384 or SHA-256
}
// written through the loan
fn through(d: &[u8]) {
    let (mut g1, mut g2): (D, D) = (&SHA256, &SHA256);
    {
        let mut s: &mut D = &mut g1;
        {
            let l = &mut s;
            if n(9) > 0 { *l = &mut g2; }
        }
        *s = &SHA512;
    }
    let _ = digest(g1, d); // SHA-512 or SHA-256
    let _ = digest(g2, d); // SHA-512 or SHA-256
}
fn main() {
    let d = arg(1);
    let d = d.as_bytes();
    coerced(d); captured(d); handed(d); swapped(d); through(d);
}
