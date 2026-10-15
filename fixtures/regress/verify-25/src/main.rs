// regress verify-25 (round 13, audit 12 M11: instantiation chains typed from the receiver's expression and a generic call's type arguments; verifier probes vr8, vr8b, vr8c, audit 12 probe g2)
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA512};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

trait Base { fn base(&self) -> &'static Digest { &SHA1 } }
trait Ext: Base { fn ext(&self) -> &'static Digest { self.base() } }
struct E1;
struct E2;
impl Base for E1 { fn base(&self) -> &'static Digest { &SHA512 } }
impl Ext for E1 {}
impl Base for E2 {}
impl Ext for E2 {}
impl E1 { fn upgrade(self) -> E2 { E2 } }
fn mk1() -> E1 { E1 }
fn mk2() -> E2 { E2 }
struct Pair { a: E1, b: E2 }

trait Pick { fn alg(&self) -> &'static Digest { &SHA256 } }
struct A;
impl Pick for A {}
struct B;
impl Pick for B { fn alg(&self) -> &'static Digest { &SHA512 } }
fn sink(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); }
fn pass<T: Pick>(t: &T, d: &[u8]) { sink(t.alg(), d) }

fn main() {
    let d = arg(0).into_bytes();
    let x = E1;
    let y = E2;
    let _ = digest(x.ext(), &d);
    let _ = digest(y.ext(), &d);
    let _ = digest(mk1().ext(), &d);
    let _ = digest(mk2().ext(), &d);
    let p = Pair { a: E1, b: E2 };
    let _ = digest(p.a.ext(), &d);
    let _ = digest(p.b.ext(), &d);
    let e = E1.upgrade();
    let _ = digest(e.ext(), &d);
    pass(&A, &d);
    pass(&B, &d);
}
