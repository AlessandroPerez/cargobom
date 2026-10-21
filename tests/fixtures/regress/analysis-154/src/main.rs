// Values holding `&mut` (a struct of the program, a tuple) handed to the program's functions that
// write through them: the cases where following those writes must not claim too much. Each call
// says what can reach it.
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
type D = &'static Digest;
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn n(i: usize) -> usize { arg(i).len() }
fn lend(r: &mut D) { if n(5) > 0 { *r = &SHA384; } }

struct W<'a> { slot: &'a mut D }
struct P2<'a> { a: &'a mut D, b: &'a mut D }
fn wset(w: W) { *w.slot = &SHA512; }
fn wmaybe(w: W) { if n(1) > 0 { *w.slot = &SHA384; } }
fn wread(w: &mut W) -> usize { w.slot.output_len() }
fn wonly_b(p: P2) { let _ = p.a.output_len(); *p.b = &SHA1; }
fn tset(t: (&mut D, u8)) { *t.0 = &SHA384; }
fn outer(w: W) { wset(w) }
fn via(w: W) { lend(w.slot) }
fn repointed<'a>(mut w: W<'a>, other: &'a mut D) { w.slot = other; *w.slot = &SHA512; }
fn escaped<'a>(w: W<'a>) -> impl FnMut() + 'a { move || *w.slot = &SHA1 }
fn rehome<'a>(h: &mut W<'a>, to: &'a mut D) { h.slot = to; }
struct Dropped<'a> { slot: &'a mut D }
impl Drop for Dropped<'_> { fn drop(&mut self) { *self.slot = &SHA1; } }
fn dset(_d: Dropped) {}
fn gset<T: AsMut<D>>(mut t: T) { *t.as_mut() = &SHA512; }
struct G<'a> { slot: &'a mut D }
impl AsMut<D> for G<'_> { fn as_mut(&mut self) -> &mut D { self.slot } }

fn main() {
    let d = arg(0).into_bytes();
    // built on one branch or the other: either may be written
    let (mut a1, mut a2): (D, D) = (&SHA256, &SHA256);
    let w = if n(2) > 0 { W { slot: &mut a1 } } else { W { slot: &mut a2 } };
    wset(w);
    let _ = digest(a1, &d); // SHA-256, SHA-512
    let _ = digest(a2, &d); // SHA-256, SHA-512
    // its field re-pointed before the call: the write lands on the other
    let (mut b1, mut b2): (D, D) = (&SHA256, &SHA256);
    let mut w = W { slot: &mut b1 };
    w.slot = &mut b2;
    wset(w);
    let _ = digest(b1, &d); // SHA-256 (+ may SHA-512)
    let _ = digest(b2, &d); // SHA-512 (+ may SHA-256)
    // re-pointed by another function before the call
    let (mut c1, mut c2): (D, D) = (&SHA256, &SHA256);
    let mut w = W { slot: &mut c1 };
    rehome(&mut w, &mut c2);
    wset(w);
    let _ = digest(c1, &d); // SHA-256 (+ may SHA-512)
    let _ = digest(c2, &d); // SHA-512 (+ may SHA-256)
    // written on one way through the function only
    let mut e1: D = &SHA256;
    wmaybe(W { slot: &mut e1 });
    let _ = digest(e1, &d); // SHA-256, SHA-384
    // only read
    let mut f1: D = &SHA256;
    let mut w = W { slot: &mut f1 };
    let _ = wread(&mut w);
    let _ = digest(f1, &d); // SHA-256
    // two borrows, one written
    let (mut g1, mut g2): (D, D) = (&SHA256, &SHA256);
    wonly_b(P2 { a: &mut g1, b: &mut g2 });
    let _ = digest(g1, &d); // SHA-256
    let _ = digest(g2, &d); // SHA-1
    // a tuple holding it
    let mut h1: D = &SHA256;
    tset((&mut h1, 0));
    let _ = digest(h1, &d); // SHA-384
    // handed on whole to another function
    let mut i1: D = &SHA256;
    outer(W { slot: &mut i1 });
    let _ = digest(i1, &d); // SHA-512 (+ may SHA-256)
    // its pointer lent to a function that may write
    let mut j1: D = &SHA256;
    via(W { slot: &mut j1 });
    let _ = digest(j1, &d); // SHA-256, SHA-384
    // the function points its field elsewhere first
    let (mut k1, mut k2): (D, D) = (&SHA256, &SHA256);
    repointed(W { slot: &mut k1 }, &mut k2);
    let _ = digest(k1, &d); // SHA-256 (+ may SHA-512)
    let _ = digest(k2, &d); // SHA-512 (+ may SHA-256)
    // the pointer escapes in a closure the function returns, run later
    let mut l1: D = &SHA256;
    let mut f = escaped(W { slot: &mut l1 });
    f();
    drop(f);
    let _ = digest(l1, &d); // SHA-1 (+ may SHA-256)
    // a holder whose destructor writes
    let mut m1: D = &SHA256;
    dset(Dropped { slot: &mut m1 });
    let _ = digest(m1, &d); // SHA-1 (+ may SHA-256)
    // a generic function writing through a trait
    let mut o1: D = &SHA256;
    gset(G { slot: &mut o1 });
    let _ = digest(o1, &d); // SHA-512 (+ may SHA-256)
}
