// audit 12 probe bnd6: control of bnd5 with 3 types
use ring::digest::{digest, Algorithm, SHA256, SHA512};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
trait P { fn alg() -> &'static Algorithm { &SHA256 } }
fn sink(a: &'static Algorithm, d: &[u8]) { let _ = digest(a, d); }
fn pass<T: P>(d: &[u8]) { sink(T::alg(), d) }
struct Last;
impl P for Last { fn alg() -> &'static Algorithm { &SHA512 } }
macro_rules! types { ($($t:ident)*) => { $(struct $t; impl P for $t {})* } }
macro_rules! calls { ($d:expr; $($t:ident)*) => { $(pass::<$t>($d);)* } }
types!(T0 T1 T2);
fn main() {
    let d = arg(0).into_bytes();
    calls!(&d; T0 T1 T2);
    pass::<Last>(&d);
}
