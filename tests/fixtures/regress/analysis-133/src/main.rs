// audit 13 probe a18: constants of enums, Options and tuples holding constants; statics of those
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
#[derive(Clone, Copy)]
struct Cfg { h: &'static Digest, legacy: &'static Digest }
const BASE: Cfg = Cfg { h: &SHA384, legacy: &SHA1 };
const OPT: Option<Cfg> = Some(BASE);
const PAIR: (Cfg, &Digest) = (BASE, &SHA512);
enum Choice { A(Cfg), B(&'static Digest) }
const CA: Choice = Choice::A(BASE);
static SPAIR: (Cfg, &Digest) = (Cfg { h: &SHA256, legacy: &SHA1 }, &SHA512);
const fn wrap(c: Cfg) -> Cfg { c }
static WRAPPED: Cfg = wrap(BASE);

fn main() {
    let d = arg(0).into_bytes();
    let _ = digest(OPT.unwrap().h, &d);
    let _ = digest(PAIR.0.legacy, &d);
    let _ = digest(PAIR.1, &d);
    let a = match CA { Choice::A(c) => c.h, Choice::B(x) => x };
    let _ = digest(a, &d);
    let _ = digest(SPAIR.0.h, &d);
    let _ = digest(SPAIR.1, &d);
    let _ = digest(WRAPPED.h, &d);
    let _ = digest(WRAPPED.legacy, &d);
}
