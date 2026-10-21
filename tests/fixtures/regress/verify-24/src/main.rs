// regress verify-24 (round 13, audit 12 M10: members from other functions by every label, witnesses; verifier probe vr4b)
use ring::digest::{digest, Algorithm, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
use std::sync::RwLock;

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

trait Pick { fn alg(&self) -> &'static Algorithm { &SHA1 } }
struct Fast;
struct Slow;
struct Old;
impl Pick for Fast { fn alg(&self) -> &'static Algorithm { &SHA512 } }
impl Pick for Slow { fn alg(&self) -> &'static Algorithm { &SHA384 } }
impl Pick for Old {}

struct Ctx { h: &'static Algorithm }
fn set_a(c: &mut Ctx) { c.h = &SHA384; }
fn set_b(c: &mut Ctx) { c.h = &SHA512; }
static CUR: RwLock<&'static Algorithm> = RwLock::new(&SHA256);
fn set_cur() { *CUR.write().unwrap() = &SHA384; }

fn run(p: &dyn Pick, _d: &[u8]) -> usize {
    let d = b"fixed".as_slice();
    let a = digest(p.alg(), d).as_ref().len();
    let b = digest(&SHA256, d).as_ref().len();
    a + b
}
fn generic<T: Pick>(t: &T, _d: &[u8]) -> usize {
    let d = b"fixed".as_slice();
    let a = digest(t.alg(), d).as_ref().len();
    let b = digest(&SHA256, d).as_ref().len();
    a + b
}
fn from_ctx(c: &Ctx, _d: &[u8]) -> usize {
    let d = b"fixed".as_slice();
    let a = digest(c.h, d).as_ref().len();
    let b = digest(&SHA256, d).as_ref().len();
    a + b
}
fn from_static(_d: &[u8]) -> usize {
    let d = b"fixed".as_slice();
    let a = digest(*CUR.read().unwrap(), d).as_ref().len();
    let b = digest(&SHA512, d).as_ref().len();
    a + b
}
fn from_vec(v: &[&'static Algorithm], i: usize, _d: &[u8]) -> usize {
    let d = b"fixed".as_slice();
    let a = digest(v[i], d).as_ref().len();
    let b = digest(&SHA1, d).as_ref().len();
    a + b
}
fn joined(_d: &[u8]) -> usize {
    let d = b"fixed".as_slice();
    let c = make();
    let a = digest(c.h, d).as_ref().len();
    let b = digest(&SHA1, d).as_ref().len();
    a + b
}
fn make() -> Ctx { Ctx { h: &SHA512 } }

fn main() {
    let d = arg(0).into_bytes();
    let n = arg(1).len();
    let p: &dyn Pick = if n > 2 { &Fast } else if n > 1 { &Slow } else { &Old };
    let _ = run(p, &d);
    let _ = generic(&Fast, &d) + generic(&Old, &d);
    let mut c = Ctx { h: &SHA256 };
    if n > 3 { set_a(&mut c) } else { set_b(&mut c) }
    let _ = from_ctx(&c, &d);
    set_cur();
    let _ = from_static(&d);
    let v = vec![&SHA384, &SHA512];
    let _ = from_vec(&v, n % 2, &d);
    let _ = joined(&d);
}
