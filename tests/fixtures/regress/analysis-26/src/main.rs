// Operations whose algorithm the analysis cannot resolve yet are reported with an unknown
// algorithm and the reason, never dropped (round 6, item 1): a trait object's result, a
// HashMap value and an iterator adapter's closure argument. A generic function whose instance
// resolves the algorithm (`by_param::<P>`) is not also unknown; one whose instance does not
// (`by_param::<Q>`, the value of a run-time static) is.
use std::collections::HashMap;

use ring::digest::{digest, Algorithm, SHA256, SHA384, SHA512};

trait Scheme {
    fn alg(&self) -> &'static Algorithm;
}
struct S384;
struct S512;
impl Scheme for S384 {
    fn alg(&self) -> &'static Algorithm {
        &SHA384
    }
}
impl Scheme for S512 {
    fn alg(&self) -> &'static Algorithm {
        &SHA512
    }
}

#[inline(never)]
fn by_dyn(s: &dyn Scheme, d: &[u8]) -> usize {
    digest(s.alg(), d).as_ref().len()
}

#[inline(never)]
fn by_map(m: &HashMap<&str, &'static Algorithm>, d: &[u8]) -> usize {
    digest(m["h"], d).as_ref().len()
}

trait Pick {
    fn alg() -> &'static Algorithm;
}
struct P;
struct Q;
impl Pick for P {
    fn alg() -> &'static Algorithm {
        &SHA256
    }
}
static CHOSEN: std::sync::OnceLock<&'static Algorithm> = std::sync::OnceLock::new();
impl Pick for Q {
    fn alg() -> &'static Algorithm {
        CHOSEN.get().copied().unwrap_or(&SHA512)
    }
}

#[inline(never)]
fn by_param<T: Pick>(d: &[u8]) -> usize {
    digest(T::alg(), d).as_ref().len()
}

fn main() {
    let d = std::env::args().next().unwrap_or_default().into_bytes();
    let s: Box<dyn Scheme> = if d.is_empty() { Box::new(S384) } else { Box::new(S512) };
    let mut m = HashMap::new();
    m.insert("h", &SHA256);
    let n: usize = [&SHA256].iter().map(|a| digest(a, &d).as_ref().len()).sum();
    let g = by_param::<P>(&d) + by_param::<Q>(&d);
    println!("{}", by_dyn(&*s, &d) + by_map(&m, &d) + n + g);
}
