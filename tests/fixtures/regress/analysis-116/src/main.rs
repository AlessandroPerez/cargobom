// audit 13 probe a1: writes through values a local function returns that hold a `&mut` (H1 variations)
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
use std::ops::{Deref, DerefMut};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
struct W<'a> { r: &'a mut &'static Digest }
impl<'a> Deref for W<'a> { type Target = &'static Digest; fn deref(&self) -> &&'static Digest { self.r } }
impl<'a> DerefMut for W<'a> { fn deref_mut(&mut self) -> &mut &'static Digest { self.r } }
fn wrap_impl<'a>(x: &'a mut &'static Digest) -> impl DerefMut<Target = &'static Digest> + 'a { W { r: x } }
fn setter<'a>(x: &'a mut &'static Digest) -> impl FnMut(&'static Digest) + 'a { move |a| *x = a }
fn boxed<'a>(x: &'a mut &'static Digest) -> Box<dyn FnMut(&'static Digest) + 'a> { Box::new(move |a| *x = a) }
fn deep<'a>(x: &'a mut &'static Digest) -> Result<Option<Box<(W<'a>, u8)>>, ()> { Ok(Some(Box::new((W { r: x }, 0)))) }
fn vec_of<'a>(x: &'a mut &'static Digest) -> Vec<&'a mut &'static Digest> { vec![x] }
fn pass<'a>(h: W<'a>) -> W<'a> { h }
struct S { alg: &'static Digest, other: &'static Digest }
impl S { fn holder(&mut self) -> W<'_> { W { r: &mut self.alg } } }
fn dyn_deref<'a>(x: &'a mut &'static Digest) -> Box<dyn DerefMut<Target = &'static Digest> + 'a> { Box::new(W { r: x }) }

fn main() {
    let d = arg(0).into_bytes();
    let mut x1: &'static Digest = &SHA256;
    { let mut w = wrap_impl(&mut x1); *w = &SHA512; }
    let _ = digest(x1, &d);
    let mut x2: &'static Digest = &SHA256;
    { let mut f = setter(&mut x2); f(&SHA384); }
    let _ = digest(x2, &d);
    let mut x3: &'static Digest = &SHA256;
    { let mut f = boxed(&mut x3); f(&SHA512); }
    let _ = digest(x3, &d);
    let mut x4: &'static Digest = &SHA256;
    if let Ok(Some(b)) = deep(&mut x4) { let (w, _) = *b; *w.r = &SHA384; }
    let _ = digest(x4, &d);
    let mut x5: &'static Digest = &SHA256;
    for r in vec_of(&mut x5) { *r = &SHA512; }
    let _ = digest(x5, &d);
    let mut x6: &'static Digest = &SHA256;
    { let w = pass(W { r: &mut x6 }); *w.r = &SHA384; }
    let _ = digest(x6, &d);
    let mut x7: &'static Digest = &SHA256;
    { let mut w = W { r: &mut x7 }; *w = &SHA512; }
    let _ = digest(x7, &d);
    let mut s1 = S { alg: &SHA256, other: &SHA1 };
    { let h = s1.holder(); *h.r = &SHA384; }
    let _ = digest(s1.alg, &d);
    let _ = digest(s1.other, &d);
    let mut x8: &'static Digest = &SHA256;
    { let mut w = dyn_deref(&mut x8); **w = &SHA512; }
    let _ = digest(x8, &d);
}
