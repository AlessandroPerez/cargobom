// an enum variant's field written through a pattern's binding (`if let E::V(a) = e { *a = v }`):
// a store in the variant's field like `E::V(v)`, so a read of that field by type sees it. Each
// case writes its own enum.
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
type D = &'static Digest;
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
enum E { V(D), W(u8) }
enum F { V(D) }
enum G { V { alg: D }, W }
enum H { V(D) }
struct S { h: H }
fn put(r: &mut D) { *r = &SHA384; }
// `if let` on `&mut E`: `a` points to the variant's field
fn bound(e: &mut E) { if let E::V(a) = e { *a = &SHA512; } }
// an irrefutable pattern, in an element of a vector
fn whole(f: &mut F) { let F::V(a) = f; *a = &SHA384; }
// a named field, by `match` with `ref mut`
fn named(g: &mut G) { match *g { G::V { ref mut alg } => *alg = &SHA1, G::W => {} } }
// the binding handed on to a function writing through it
fn handed(e: &mut E) { if let E::V(a) = e { put(a); } }
// in a struct's field
fn inner(s: &mut S) { let H::V(a) = &mut s.h; *a = &SHA512; }
fn main() {
    let d = arg(0).into_bytes();
    let mut e1 = E::V(&SHA256);
    bound(&mut e1);
    if let E::V(a) = e1 { let _ = digest(a, &d); } // SHA-512 (and the variant's other values)
    let mut v2 = vec![F::V(&SHA256)];
    whole(&mut v2[0]);
    let F::V(a2) = v2[0];
    let _ = digest(a2, &d); // SHA-384
    let mut g3 = G::V { alg: &SHA256 };
    named(&mut g3);
    if let G::V { alg } = g3 { let _ = digest(alg, &d); } // SHA-1
    let mut e4 = E::V(&SHA256);
    handed(&mut e4);
    if let E::V(a) = e4 { let _ = digest(a, &d); } // SHA-384
    let mut s5 = S { h: H::V(&SHA256) };
    inner(&mut s5);
    let H::V(a5) = s5.h;
    let _ = digest(a5, &d); // SHA-512
    let _ = (E::W(1), G::W);
}
