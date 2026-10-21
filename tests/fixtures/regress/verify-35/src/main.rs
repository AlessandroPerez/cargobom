// round 14 regress (audit 13 verifier probe vo5): ordinary value flows
use ring::digest::{digest, Algorithm, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

struct Cfg { alg: &'static Algorithm, old: Option<&'static Algorithm> }
impl Cfg {
    const DEFAULT_ALG: &'static Algorithm = &SHA384;
    fn new() -> Self { Cfg { alg: Self::DEFAULT_ALG, old: Some(&SHA1) } }
}
trait HasAlg { const ALG: &'static Algorithm = &SHA256; }
struct Plain;
struct Strong;
impl HasAlg for Plain {}
impl HasAlg for Strong { const ALG: &'static Algorithm = &SHA512; }
fn by_const<T: HasAlg>(d: &[u8]) -> usize { digest(T::ALG, d).as_ref().len() }
static LIST: &[&Algorithm] = &[&SHA256, &SHA384];

fn main() {
    let d = arg(0).into_bytes();
    let n = d.len();
    let x;
    if n > 2 { x = &SHA384; } else { x = &SHA512; }
    let _ = digest(x, &d);
    let (a, b) = if n > 3 { (&SHA256, &SHA1) } else { (&SHA1, &SHA256) };
    let _ = digest(a, &d);
    let _ = digest(b, &d);
    let c = (n > 4).then(|| &SHA512).unwrap_or(&SHA256);
    let _ = digest(c, &d);
    let mut cfg = Cfg::new();
    let prev = cfg.old.take();
    let _ = digest(cfg.alg, &d);
    if let Some(p) = prev { let _ = digest(p, &d); }
    let old = std::mem::replace(&mut cfg.alg, &SHA512);
    let _ = digest(old, &d);
    let _ = digest(cfg.alg, &d);
    let _ = by_const::<Plain>(&d) + by_const::<Strong>(&d);
    for al in LIST.iter() {
        let _ = digest(al, &d);
    }
    let m = match n { 0 => &SHA1, k if k > 10 => &SHA512, _ => &SHA256 };
    let _ = digest(m, &d);
    let mut z = &SHA256;
    {
        let z = &SHA384;
        let _ = digest(z, &d);
    }
    z = if n > 6 { &SHA1 } else { z };
    let _ = digest(z, &d);
}
