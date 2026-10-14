// round 12 regress (audit 11 probe dy1): trait objects with supertrait default bodies, upcasts, blanket impls, defaults calling overridden methods
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

trait Super { fn sup(&self) -> &'static Digest { &SHA1 } fn via(&self) -> &'static Digest { self.sup() } }
trait Sub: Super { fn sub(&self) -> &'static Digest { self.sup() } }
struct S1;
struct S2;
impl Super for S1 { fn sup(&self) -> &'static Digest { &SHA256 } }
impl Sub for S1 {}
impl Super for S2 {}
impl Sub for S2 {}
trait Base { fn base(&self) -> &'static Digest; }
trait Pick { fn alg(&self) -> &'static Digest; }
impl<T: Base> Pick for T { fn alg(&self) -> &'static Digest { self.base() } }
struct B1;
impl Base for B1 { fn base(&self) -> &'static Digest { &SHA384 } }
struct W<T>(T);
trait Gen { fn alg(&self) -> &'static Digest { &SHA1 } }
impl Gen for W<S1> { fn alg(&self) -> &'static Digest { &SHA512 } }
impl Gen for W<S2> {}

fn main() {
    let d = arg(0).into_bytes();
    let s: &dyn Sub = if arg(1).is_empty() { &S1 } else { &S2 };
    let _ = digest(s.sub(), &d);
    let _ = digest(s.via(), &d);
    let up: &dyn Super = s;
    let _ = digest(up.sup(), &d);
    let one: &dyn Sub = &S1;
    let _ = digest(one.via(), &d);
    let p: &dyn Pick = &B1;
    let _ = digest(p.alg(), &d);
    let _ = digest(B1.alg(), &d);
    let g: &dyn Gen = &W(S2);
    let _ = digest(g.alg(), &d);
    let _ = digest(W(S1).alg(), &d);
}
