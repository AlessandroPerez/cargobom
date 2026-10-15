// round 14 regress (audit 13 verifier probe vch3): receivers whose type the code says
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA512};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

trait Base { fn base(&self) -> &'static Digest { &SHA1 } }
trait Ext: Base { fn ext(&self) -> &'static Digest { self.base() } }
#[derive(Default, Clone, Copy)]
struct E1;
struct E2;
impl Base for E1 { fn base(&self) -> &'static Digest { &SHA512 } }
impl Ext for E1 {}
impl Base for E2 {}
impl Ext for E2 {}
type Alias = E1;
type A2 = E2;
struct Gen<T> { inner: T }
fn pair() -> (E1, E2) { (E1, E2) }
fn boxed() -> Box<E1> { Box::new(E1) }

fn main() {
    let d = arg(0).into_bytes();
    let a2: A2 = E2;
    let _ = digest(a2.ext(), &d);
    let _ = digest(E2.ext(), &d);
    let _ = digest(pair().0.ext(), &d);
    let _ = digest(boxed().ext(), &d);
    let arr = [E1, E1];
    let _ = digest(arr[0].ext(), &d);
    let opt = Some(E1);
    let _ = digest(opt.unwrap().ext(), &d);
    let e1 = E1;
    let _ = digest((&e1).ext(), &d);
    let _ = digest(E1::default().ext(), &d);
    let _ = digest(if d.len() > 2 { E1 } else { E1 }.ext(), &d);
    let a: Alias = E1;
    let _ = digest(a.ext(), &d);
    let g = Gen { inner: E1 };
    let _ = digest(g.inner.ext(), &d);
    let r: &E1 = &e1;
    let _ = digest(r.ext(), &d);
    let c = e1.clone();
    let _ = digest(c.ext(), &d);
}
