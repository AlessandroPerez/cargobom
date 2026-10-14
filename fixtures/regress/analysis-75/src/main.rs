// round 12 regress (audit 11 probe gi1): generic instances: default bodies calling overridden methods, nested generics, generic impls, generic methods, assoc fns, closures, supertraits
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

trait Pick {
    fn alg(&self) -> &'static Digest { &SHA256 }
    fn via(&self) -> &'static Digest { self.alg() }
}
struct Fast;
struct Legacy;
impl Pick for Fast { fn alg(&self) -> &'static Digest { &SHA384 } }
impl Pick for Legacy {}

fn outer<T: Pick>(t: &T) -> &'static Digest { inner(t) }
fn inner<U: Pick>(u: &U) -> &'static Digest { u.alg() }

struct W<T>(T);
trait Gen { fn alg(&self) -> &'static Digest; }
impl<T: Pick> Gen for W<T> { fn alg(&self) -> &'static Digest { self.0.alg() } }

struct Holder;
impl Holder { fn pick<T: Pick>(&self, t: &T) -> &'static Digest { t.alg() } }

trait Assoc { fn make() -> &'static Digest; }
struct A1;
struct A2;
impl Assoc for A1 { fn make() -> &'static Digest { &SHA512 } }
impl Assoc for A2 { fn make() -> &'static Digest { &SHA1 } }
fn assoc<T: Assoc>() -> &'static Digest { T::make() }

fn clos<T: Pick>(t: &T) -> &'static Digest { let f = || t.alg(); f() }

trait Base { fn base(&self) -> &'static Digest { &SHA1 } }
trait Ext: Base { fn ext(&self) -> &'static Digest { self.base() } }
struct E1;
struct E2;
impl Base for E1 { fn base(&self) -> &'static Digest { &SHA512 } }
impl Ext for E1 {}
impl Base for E2 {}
impl Ext for E2 {}

fn two<T: Pick, U: Assoc>(t: &T) -> &'static Digest { if arg(9).is_empty() { t.alg() } else { U::make() } }

fn by_ref<T: Pick + ?Sized>(t: &T) -> &'static Digest { t.alg() }

fn gsite<T: Pick>(t: &T, d: &[u8]) { let _ = digest(t.via(), d); }

fn main() {
    let d = arg(0).into_bytes();
    let _ = digest(Fast.via(), &d);
    let _ = digest(Legacy.via(), &d);
    let _ = digest(outer(&Fast), &d);
    let _ = digest(outer(&Legacy), &d);
    let _ = digest(W(Fast).alg(), &d);
    let _ = digest(W(Legacy).alg(), &d);
    let _ = digest(Holder.pick(&Fast), &d);
    let _ = digest(assoc::<A1>(), &d);
    let _ = digest(assoc::<A2>(), &d);
    let _ = digest(clos(&Fast), &d);
    let _ = digest(E1.ext(), &d);
    let _ = digest(E2.ext(), &d);
    let _ = digest(two::<Fast, A1>(&Fast), &d);
    let g: &dyn Gen = &W(Legacy);
    let _ = digest(g.alg(), &d);
    let _ = digest(by_ref(&Fast), &d);
    let p: &dyn Pick = &Fast;
    let _ = digest(by_ref(p), &d);
    gsite(&Fast, &d);
    if arg(2) == "legacy" { gsite(&Legacy, &d); }
}
