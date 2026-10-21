// round 11 regress (audit 10 probe d2): trait-object results: receiver data not used, field paths, nested dispatch
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

trait Pick { fn alg(&self) -> &'static Digest; }
struct Ignores { a: &'static Digest }
impl Pick for Ignores { fn alg(&self) -> &'static Digest { &SHA1 } }
struct Plain { a: &'static Digest }
impl Plain { fn pick(&self) -> &'static Digest { &SHA384 } }

#[derive(Clone, Copy)]
struct Cfg { alg: &'static Digest, other: &'static Digest }
trait Conf { fn cfg(&self) -> Cfg; }
struct C1;
struct C2;
impl Conf for C1 { fn cfg(&self) -> Cfg { Cfg { alg: &SHA256, other: &SHA1 } } }
impl Conf for C2 { fn cfg(&self) -> Cfg { Cfg { alg: &SHA384, other: &SHA1 } } }

trait Chain { fn alg(&self) -> &'static Digest; }
struct Leaf;
impl Chain for Leaf { fn alg(&self) -> &'static Digest { &SHA512 } }
struct Wrapper { inner: Box<dyn Chain> }
impl Chain for Wrapper { fn alg(&self) -> &'static Digest { self.inner.alg() } }

fn main() {
    let d = arg(0).into_bytes();
    // the object holds SHA-512, the method returns SHA-1
    let p: Box<dyn Pick> = Box::new(Ignores { a: &SHA512 });
    let _ = digest(p.alg(), &d);
    let q = Plain { a: &SHA512 };
    let _ = digest(q.pick(), &d);
    // a field of a struct a trait object's method returns
    let c: Box<dyn Conf> = if arg(1).is_empty() { Box::new(C1) } else { Box::new(C2) };
    let _ = digest(c.cfg().alg, &d);
    // nested dispatch: a wrapper around another trait object of the same trait
    let w: Box<dyn Chain> = Box::new(Wrapper { inner: Box::new(Leaf) });
    let _ = digest(w.alg(), &d);
    let _ = (p.alg(), q.a, c.cfg().other);
    if let Some(x) = Some(Ignores { a: &SHA256 }) { let _ = x.a; }
    let _ = Plain { a: &SHA256 }.a;
    let _ = d.len();
    let _ = q.a;
    let _ = std::hint::black_box(&p);
}
