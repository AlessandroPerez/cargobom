// Holders of `&mut` handed to the program's functions as a part of another value (`set(o.w)`) or
// as an `Option<&mut>`: the cases where following them must not claim too much. Each call says
// what can reach it.
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
type D = &'static Digest;
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn n(i: usize) -> usize { arg(i).len() }

struct W<'a> { r: &'a mut D }
struct Outer<'a> { w: W<'a>, tag: u8 }
struct Outer2<'a> { o: Outer<'a> }
fn set(w: W) { *w.r = &SHA512; }
fn repoint<'a>(o: &mut Outer<'a>, b: &'a mut D) { if n(1) > 0 { o.w.r = b; } }
fn opt_set(o: Option<&mut D>) { if let Some(s) = o { *s = &SHA384; } }
fn opt_maybe(o: Option<&mut D>) { if let Some(s) = o { if n(2) > 0 { *s = &SHA512; } } }
fn opt_re<'a>(mut o: Option<&'a mut D>, b: &'a mut D) { if n(3) > 0 { o = Some(b); } if let Some(s) = o { *s = &SHA1; } }
fn opt_take(mut o: Option<&mut D>) { if let Some(s) = o.take() { *s = &SHA384; } }
fn opt_pass(o: Option<&mut D>) -> Option<&mut D> { o }
fn opt_two(o: Option<&mut D>, p: Option<&mut D>) { if let Some(s) = o { *s = &SHA384; } if let Some(t) = p { *t = &SHA512; } }

fn main() {
    let d = arg(0).into_bytes();
    // a holder moved out of the struct it was built in, then written by the function
    let mut a1: D = &SHA256;
    { let o = Outer { w: W { r: &mut a1 }, tag: 1 }; let _ = o.tag; set(o.w); }
    let _ = digest(a1, &d); // SHA-512
    // two levels deep, and a tuple's element
    let mut a2: D = &SHA256;
    { let o2 = Outer2 { o: Outer { w: W { r: &mut a2 }, tag: 2 } }; set(o2.o.w); }
    let _ = digest(a2, &d); // SHA-512
    let mut a3: D = &SHA256;
    { let t = (W { r: &mut a3 }, 3u8); set(t.0); }
    let _ = digest(a3, &d); // SHA-512
    // the struct lent to a function that may re-point the holder first: either written
    let (mut a4, mut b4): (D, D) = (&SHA256, &SHA256);
    { let mut o = Outer { w: W { r: &mut a4 }, tag: 4 }; repoint(&mut o, &mut b4); set(o.w); }
    let _ = digest(a4, &d); // SHA-256, SHA-512
    let _ = digest(b4, &d); // SHA-256, SHA-512
    // the holder replaced in the struct before it is handed over: the first variable is not written
    let (mut a5, mut b5): (D, D) = (&SHA256, &SHA384);
    { let mut o = Outer { w: W { r: &mut a5 }, tag: 5 }; o.w = W { r: &mut b5 }; set(o.w); }
    let _ = digest(a5, &d); // SHA-256
    let _ = digest(b5, &d); // SHA-512
    // `Some(&mut x)` handed over, written when `Some`
    let mut c1: D = &SHA256;
    opt_set(Some(&mut c1));
    let _ = digest(c1, &d); // SHA-384
    // `None` on one way
    let mut c2: D = &SHA256;
    opt_set(if n(4) > 0 { Some(&mut c2) } else { None });
    let _ = digest(c2, &d); // SHA-256, SHA-384
    // written on one way inside the function
    let mut c3: D = &SHA256;
    opt_maybe(Some(&mut c3));
    let _ = digest(c3, &d); // SHA-256, SHA-512
    // re-pointed inside the function to its other parameter: either written
    let (mut c4, mut d4): (D, D) = (&SHA256, &SHA256);
    opt_re(Some(&mut c4), &mut d4);
    let _ = digest(c4, &d); // SHA-256, SHA-1
    let _ = digest(d4, &d); // SHA-256, SHA-1
    // taken out with `Option::take` and written
    let mut c5: D = &SHA256;
    opt_take(Some(&mut c5));
    let _ = digest(c5, &d); // SHA-384
    // handed back and written by the caller
    let mut c6: D = &SHA256;
    if let Some(r) = opt_pass(Some(&mut c6)) { *r = &SHA1; }
    let _ = digest(c6, &d); // SHA-1
    // two of them, each written with its own value
    let (mut c7, mut d7): (D, D) = (&SHA256, &SHA256);
    opt_two(Some(&mut c7), Some(&mut d7));
    let _ = digest(c7, &d); // SHA-384
    let _ = digest(d7, &d); // SHA-512
    // an `Option` built once and lent to the function by `&mut` after: not a holder handed over
    let mut c8: D = &SHA256;
    let mut o8 = Some(&mut c8);
    if let Some(s) = o8.as_mut() { **s = &SHA384; }
    opt_set(o8);
    let _ = digest(c8, &d); // SHA-384
}
