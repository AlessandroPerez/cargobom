// round 11 regress (audit 10 probe p2): pointers in statics, closures, dyn Fn, containers
use ring::digest::{self, digest, Algorithm as Digest, Digest as Out, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
use std::collections::HashMap;
use std::rc::Rc;

type HashFn = fn(&'static Digest, &[u8]) -> Out;
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

fn my1(a: &'static Digest, d: &[u8]) -> Out { digest(a, d) }
fn my2(a: &'static Digest, d: &[u8]) -> Out { digest(a, d) }
fn my3(a: &'static Digest, d: &[u8]) -> Out { digest(a, d) }
fn my4(a: &'static Digest, d: &[u8]) -> Out { digest(a, d) }
fn my5(a: &'static Digest, d: &[u8]) -> Out { digest(a, d) }
fn my6(a: &'static Digest, d: &[u8]) -> Out { digest(a, d) }
fn my7(a: &'static Digest, d: &[u8]) -> Out { digest(a, d) }
fn my8(a: &'static Digest, d: &[u8]) -> Out { digest(a, d) }

static A: HashFn = my1;
static B: &HashFn = &A;
static C: &&HashFn = &B;
static FNS: [HashFn; 2] = [my2, digest::digest];
static DYN: &(dyn Fn(&'static Digest, &[u8]) -> Out + Sync) = &my3;
struct Ops { h: HashFn }
static OPS: Ops = Ops { h: my4 };

fn main() {
    let d = arg(0).into_bytes();
    let i = arg(1).len() % 2;
    A(&SHA1, &d);
    (*B)(&SHA256, &d);
    (**C)(&SHA384, &d);
    FNS[i](&SHA512, &d);
    DYN(&SHA1, &d);
    (OPS.h)(&SHA256, &d);
    let mk = || my5 as HashFn;
    mk()(&SHA384, &d);
    let b: Box<dyn Fn(&'static Digest, &[u8]) -> Out> = Box::new(my6);
    b(&SHA512, &d);
    let r: Rc<dyn Fn(&'static Digest, &[u8]) -> Out> = Rc::new(digest::digest);
    r(&SHA1, &d);
    let mut cnt = 0;
    let mut fm = |a: &'static Digest, x: &[u8]| { cnt += 1; digest(a, x) };
    let g: &mut dyn FnMut(&'static Digest, &[u8]) -> Out = &mut fm;
    g(&SHA256, &d);
    let m: HashMap<&str, HashFn> = HashMap::from([("a", my7 as HashFn)]);
    m["a"](&SHA384, &d);
    let arr = [digest::digest as HashFn, my8];
    for f in arr { f(&SHA512, &d); }
}
