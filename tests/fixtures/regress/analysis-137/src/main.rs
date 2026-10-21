// audit 13 probe gs1: generic items whose instances are reached by pointers, vtables, closures
use ring::digest::{digest, Algorithm as Digest, SHA256, SHA384, SHA512};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
trait Pick { fn alg(&self) -> &'static Digest { &SHA256 } }
struct A;
impl Pick for A {}
struct B;
impl Pick for B { fn alg(&self) -> &'static Digest { &SHA512 } }
struct C;
impl Pick for C { fn alg(&self) -> &'static Digest { &SHA384 } }
fn sink1(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); }
fn pass1<T: Pick>(t: &T, d: &[u8]) { sink1(t.alg(), d) }
fn sink2(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); }
trait Run { fn run(&self, d: &[u8]); }
struct W<T>(T);
impl<T: Pick> Run for W<T> { fn run(&self, d: &[u8]) { sink2(self.0.alg(), d) } }
fn sink3(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); }
fn pass3<T: Pick>(t: &T, d: &[u8]) { let f = || sink3(t.alg(), d); f() }
fn sink4(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); }
fn pass4<T: Pick>(t: &T, d: &[u8]) { sink4(t.alg(), d) }
static TABLE: [fn(&C, &[u8]); 1] = [pass4::<C>];

fn main() {
    let d = arg(0).into_bytes();
    pass1(&A, &d);
    let f: fn(&C, &[u8]) = pass1::<C>;
    f(&C, &d);
    W(B).run(&d);
    let r: &dyn Run = &W(C);
    r.run(&d);
    pass3(&A, &d);
    pass3(&C, &d);
    pass4(&B, &d);
    TABLE[0](&C, &d);
}
