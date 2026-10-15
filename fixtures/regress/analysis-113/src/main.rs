// audit 12 probe pi1: per-item sites beside walked instances: macros in live and dead fns, generic fns, closures
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
macro_rules! h { ($a:expr, $d:expr) => { let _ = digest($a, $d); } }
macro_rules! hh { ($d:expr) => { h!(&SHA384, $d) } }
trait Pick { fn alg(&self) -> &'static Digest; }
struct Fast;
impl Pick for Fast { fn alg(&self) -> &'static Digest { &SHA512 } }
struct Old;
impl Pick for Old { fn alg(&self) -> &'static Digest { &SHA1 } }
fn live(d: &[u8]) { h!(&SHA256, d); }
#[allow(dead_code)]
fn dead_fn(d: &[u8]) { h!(&SHA1, d); }
fn gen1<T: Pick>(t: &T, d: &[u8]) { let _ = digest(t.alg(), d); }
#[allow(dead_code)]
fn dead_gen_caller(d: &[u8]) { gen1(&Old, d); }
fn gen_mac<T: Pick>(_t: &T, d: &[u8]) { hh!(d); }
#[allow(dead_code)]
fn dead_hh(d: &[u8]) { hh!(d); }
fn gen_clos<T: Pick>(t: &T, d: &[u8]) { let f = |x: &[u8]| { let _ = digest(t.alg(), x); }; f(d); }

fn main() {
    let d = arg(0).into_bytes();
    live(&d);
    gen1(&Fast, &d);
    gen_mac(&Fast, &d);
    gen_clos(&Fast, &d);
}
