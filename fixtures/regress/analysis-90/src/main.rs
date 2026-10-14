// audit 11 probe bnd4 (control for bnd3, 3 types): a generic writer's instance beyond the driver's 4096 instance summaries
use ring::digest::{digest, Algorithm, SHA256, SHA512};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
trait P { fn alg() -> &'static Algorithm { &SHA256 } }
fn wr<T: P>(s: &mut &'static Algorithm) { *s = T::alg(); }
struct Last;
impl P for Last { fn alg() -> &'static Algorithm { &SHA512 } }
macro_rules! types { ($($t:ident)*) => { $(struct $t; impl P for $t {})* } }
macro_rules! calls { ($($t:ident)*) => { $({ let mut s: &'static Algorithm = &SHA256; wr::<$t>(&mut s); })* } }
types!(T0 T1 T2);
fn main() {
    let d = arg(0).into_bytes();
    calls!(T0 T1 T2);
    use_last(&d);
}
fn use_last(d: &[u8]) {
    let mut s: &'static Algorithm = &SHA256;
    wr::<Last>(&mut s);
    let _ = digest(s, d);
}
