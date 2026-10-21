// a part of a value lent by `&mut` (`set(&mut o.w)`, `&mut t.1`, `&mut ws[0]`) that holds a
// `&mut`: a write through what it holds is not followed, the place it points to may hold the
// written value (the unknown), never only what it held. A part holding no `&mut` stays exact.
use ring::digest::{digest, Algorithm as Digest, SHA256, SHA384, SHA512};
type D = &'static Digest;
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
struct W<'a> { r: &'a mut D }
struct O<'a> { w: W<'a>, n: u8 }
struct S { alg: D, n: u8 }
fn set(w: &mut W) { *w.r = &SHA384; }
fn put(r: &mut D) { *r = &SHA512; }
fn main() {
    let d = arg(0).into_bytes();
    let mut a1: D = &SHA256;
    { let mut o = O { w: W { r: &mut a1 }, n: 0 }; set(&mut o.w); let _ = o.n; }
    let _ = digest(a1, &d); // SHA-384
    let mut a2: D = &SHA256;
    { let mut t = (0u8, W { r: &mut a2 }); set(&mut t.1); }
    let _ = digest(a2, &d); // SHA-384
    let mut a3: D = &SHA256;
    let mut b3: D = &SHA256;
    { let mut ws = [W { r: &mut a3 }, W { r: &mut b3 }]; set(&mut ws[0]); }
    let _ = digest(a3, &d); // SHA-384
    let mut s4 = S { alg: &SHA256, n: 0 };
    put(&mut s4.alg);
    let _ = digest(s4.alg, &d); // SHA-512
    let _ = s4.n;
}
