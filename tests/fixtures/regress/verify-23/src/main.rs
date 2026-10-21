// regress verify-23 (round 13, audit 12 M9 and H3: table members tied to the call and the field it reads, through constants, nested fields, tuple elements, a `const fn`)
use ring::digest::{digest, Algorithm, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

#[derive(Clone, Copy)]
struct Cfg { h: &'static Algorithm, legacy: &'static Algorithm }
struct Outer { inner: Cfg, tag: u8 }

static TABLE: [Cfg; 2] = [Cfg { h: &SHA256, legacy: &SHA1 }, Cfg { h: &SHA384, legacy: &SHA1 }];
static PAIRS: [(&Algorithm, &Algorithm); 2] = [(&SHA256, &SHA1), (&SHA384, &SHA512)];
static NESTED: [Outer; 1] = [Outer { inner: Cfg { h: &SHA512, legacy: &SHA1 }, tag: 0 }];
static PLAIN1: [&Algorithm; 2] = [&SHA256, &SHA384];
static PLAIN2: [&Algorithm; 2] = [&SHA384, &SHA512];
const BASE: Cfg = Cfg { h: &SHA256, legacy: &SHA1 };
const OUT: Outer = Outer { inner: BASE, tag: 1 };
static ARR: [Cfg; 2] = [BASE, Cfg { h: &SHA512, legacy: &SHA1 }];
const fn make() -> Cfg { Cfg { h: &SHA384, legacy: &SHA1 } }
static MADE: Cfg = make();
static TS: (Cfg, Cfg) = (Cfg { h: &SHA384, legacy: &SHA1 }, Cfg { h: &SHA512, legacy: &SHA1 });

fn by_param(i: usize, d: &[u8]) -> usize {
    let a = digest(TABLE[i].h, d).as_ref().len();
    let b = digest(TABLE[i].legacy, d).as_ref().len();
    let c = digest(PLAIN1[i], d).as_ref().len();
    let e = digest(PLAIN2[i], d).as_ref().len();
    a + b + c + e
}

fn main() {
    let d = arg(0).into_bytes();
    let i = arg(1).len() % 2;
    let _ = digest(TABLE[i].h, &d);
    let _ = digest(PAIRS[i].0, &d);
    let _ = digest(PAIRS[i].1, &d);
    let _ = digest(NESTED[0].inner.h, &d);
    let _ = digest(NESTED[0].inner.legacy, &d);
    let _ = by_param(i, &d);
    let _ = digest(OUT.inner.h, &d);
    let _ = digest(ARR[i].h, &d);
    let _ = digest(MADE.h, &d);
    let _ = digest(TS.1.h, &d);
    let _ = NESTED[0].tag + OUT.tag;
}
