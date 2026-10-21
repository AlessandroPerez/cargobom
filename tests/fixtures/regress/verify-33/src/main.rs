// round 14 regress (audit 13 verifier probe vc2): each type first coerced in a different shape
use ring::digest::{digest, Algorithm, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
use std::collections::HashMap;
use std::rc::Rc;

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

trait Pick { fn alg(&self) -> &'static Algorithm; }
trait Sub: Pick {}
macro_rules! ty {
    ($t:ident, $a:ident) => {
        struct $t;
        impl Pick for $t { fn alg(&self) -> &'static Algorithm { &$a } }
    };
}
ty!(T1, SHA256);
ty!(T2, SHA384);
ty!(T3, SHA512);
ty!(T4, SHA1);
ty!(T5, SHA256);
ty!(T6, SHA384);
ty!(T7, SHA512);
ty!(T8, SHA1);
ty!(T9, SHA256);
ty!(T10, SHA384);
ty!(T11, SHA512);
ty!(T12, SHA1);
ty!(T13, SHA256);
ty!(T14, SHA384);
impl Sub for T7 {}

type BoxPick = Box<dyn Pick>;
struct Holder { p: Box<dyn Pick> }
struct Wrap(Box<dyn Pick>);
enum Slot { One(Box<dyn Pick>), None }
struct Reg { all: Vec<Box<dyn Pick>> }
impl Reg {
    fn add(&mut self, p: Box<dyn Pick>) { self.all.push(p); }
}
fn boxit<T: Pick + 'static>(t: T) -> Box<dyn Pick> { Box::new(t) }
fn choose(n: usize) -> Box<dyn Pick> {
    match n {
        0 => Box::new(T9),
        _ => Box::new(T10),
    }
}
static ST: &(dyn Pick + Sync) = &T13;
fn run(p: &dyn Pick, d: &[u8]) -> usize { digest(p.alg(), d).as_ref().len() }

fn main() {
    let d = arg(0).into_bytes();
    let n = arg(1).len();
    let a: BoxPick = Box::new(T1);
    let mut h = Holder { p: Box::new(T14) };
    h.p = Box::new(T2);
    let mut r = Reg { all: Vec::new() };
    r.add(Box::new(T3));
    let mut v: Vec<Box<dyn Pick>> = Vec::new();
    v.push(Box::new(T4));
    let b = boxit(T5);
    let rc: Rc<dyn Pick> = Rc::new(T6);
    let s: &dyn Sub = &T7;
    let o: Option<Box<dyn Pick>> = Some(Box::new(T8));
    let c = choose(n);
    let w = Wrap(Box::new(T11));
    let e = Slot::One(Box::new(T12));
    let mut m: HashMap<u8, Box<dyn Pick>> = HashMap::new();
    m.insert(1, Box::new(T1));
    let _ = run(a.as_ref(), &d) + run(h.p.as_ref(), &d) + run(r.all[0].as_ref(), &d);
    let _ = run(v[0].as_ref(), &d) + run(b.as_ref(), &d) + run(rc.as_ref(), &d);
    let _ = digest(s.alg(), &d);
    let _ = run(o.unwrap().as_ref(), &d) + run(c.as_ref(), &d) + run(w.0.as_ref(), &d);
    if let Slot::One(p) = e { let _ = run(p.as_ref(), &d); }
    let _ = run(ST, &d) + run(m[&1].as_ref(), &d);
    let _ = Slot::None;
}
