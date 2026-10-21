// audit 12 probe g2: generic helpers handing a trait method's result to non-generic code (calls and field stores of the generic item)
use ring::digest::{digest, Algorithm as Digest, SHA256, SHA512};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
trait Pick { fn alg(&self) -> &'static Digest { &SHA256 } }
struct A;
impl Pick for A {}
struct B;
impl Pick for B { fn alg(&self) -> &'static Digest { &SHA512 } }
struct Holder { a: &'static Digest }
fn sink(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); }
fn pass<T: Pick>(t: &T, d: &[u8]) { sink(t.alg(), d) }
fn hold<T: Pick>(t: &T) -> Holder { Holder { a: t.alg() } }
fn use_holder(h: &Holder, d: &[u8]) { let _ = digest(h.a, d); }

fn main() {
    let d = arg(0).into_bytes();
    pass(&A, &d);
    pass(&B, &d);
    let h = hold(&B);
    use_holder(&h, &d);
}
