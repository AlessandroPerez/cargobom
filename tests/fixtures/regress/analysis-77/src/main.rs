// round 12 regress (audit 11 probe gi3): generic instances reached through pointers, trait objects of another crate's generic impls, generic statics
use picklib::{boxed, Gen, L384, Pick, W};
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA512};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

struct Fast;
impl Pick for Fast { fn alg(&self) -> &'static Digest { &SHA512 } }
trait Local { fn alg(&self) -> &'static Digest { &SHA1 } }
struct Over;
impl Local for Over { fn alg(&self) -> &'static Digest { &SHA256 } }
fn pick<T: Pick>(t: &T) -> &'static Digest { t.alg() }
fn lpick<T: Local>(t: &T) -> &'static Digest { t.alg() }
struct Holder { f: fn(&Over) -> &'static Digest }

fn main() {
    let d = arg(0).into_bytes();
    let g: &dyn Gen = &W(Fast);
    let _ = digest(g.alg(), &d);
    let b = boxed(L384);
    let _ = digest(b.alg(), &d);
    let f: fn(&Fast) -> &'static Digest = pick::<Fast>;
    let _ = digest(f(&Fast), &d);
    let h = Holder { f: lpick::<Over> };
    let _ = digest((h.f)(&Over), &d);
    let v: Vec<&'static Digest> = [Over].iter().map(lpick).collect();
    let _ = digest(v[0], &d);
    let lo: Box<dyn Local> = Box::new(Over);
    let _ = digest(lo.alg(), &d);
}
