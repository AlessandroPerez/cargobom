// round 14 regress (audit 13 verifier probe vc5): traits with generics, paths, aliases, markers
use ring::digest::{digest, Algorithm, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

mod m {
    pub trait Pick { fn alg(&self) -> &'static ring::digest::Algorithm; }
}
use m::Pick as Chooser;
trait Gen<T> { fn alg(&self, t: T) -> &'static Algorithm; }

struct A;
struct B;
struct C;
struct D;
impl m::Pick for A { fn alg(&self) -> &'static Algorithm { &SHA256 } }
impl Chooser for B { fn alg(&self) -> &'static Algorithm { &SHA384 } }
impl Gen<u8> for C { fn alg(&self, _t: u8) -> &'static Algorithm { &SHA512 } }
impl Gen<u8> for D { fn alg(&self, _t: u8) -> &'static Algorithm { &SHA1 } }

fn run(p: &dyn m::Pick, d: &[u8]) -> usize { digest(p.alg(), d).as_ref().len() }
fn run_send(p: &(dyn Chooser + Send), d: &[u8]) -> usize { digest(p.alg(), d).as_ref().len() }
fn run_gen(p: &dyn Gen<u8>, d: &[u8]) -> usize { digest(p.alg(1), d).as_ref().len() }

fn main() {
    let d = arg(0).into_bytes();
    let a: Box<dyn crate::m::Pick> = Box::new(A);
    let _ = run(a.as_ref(), &d);
    let _ = run_send(&B, &d);
    let c: &dyn Gen<u8> = &C;
    let _ = run_gen(c, &d);
    let _ = run_gen(&D, &d);
}
