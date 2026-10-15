// round 14 regress (audit 13 verifier probe vt1): tables in ordinary shapes
use ring::digest::{digest, Algorithm, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

struct Cfg { h: &'static Algorithm, legacy: &'static Algorithm }
struct Outer { name: &'static str, inner: Cfg }
static TABLE: [Cfg; 2] = [
    Cfg { h: &SHA256, legacy: &SHA1 },
    Cfg { h: &SHA384, legacy: &SHA1 },
];
static PAIRS: [(&Algorithm, u8); 2] = [(&SHA512, 1), (&SHA256, 2)];
static OUTERS: [Outer; 1] = [Outer { name: "a", inner: Cfg { h: &SHA512, legacy: &SHA1 } }];
const BASE: Cfg = Cfg { h: &SHA384, legacy: &SHA1 };
static WITH_BASE: [Cfg; 2] = [BASE, Cfg { h: &SHA512, legacy: &SHA1 }];

fn by_slice(t: &[Cfg], i: usize, d: &[u8]) -> usize { digest(t[i].h, d).as_ref().len() }

fn main() {
    let d = arg(0).into_bytes();
    let i = arg(1).len() % 2;
    let e = &TABLE[i];
    let _ = digest(e.h, &d);
    let _ = digest(e.legacy, &d);
    for c in TABLE.iter() {
        let _ = digest(c.h, &d);
    }
    let _ = digest(PAIRS[i].0, &d);
    let (alg, _) = PAIRS[i];
    let _ = digest(alg, &d);
    let _ = digest(OUTERS[0].inner.h, &d);
    let _ = digest(WITH_BASE[i].h, &d);
    let _ = by_slice(&TABLE, i, &d);
    let found = TABLE.iter().find(|c| c.h.output_len() > i).map(|c| c.h).unwrap_or(&SHA512);
    let _ = digest(found, &d);
    let Cfg { h, legacy } = &TABLE[i];
    let _ = digest(h, &d);
    let _ = digest(legacy, &d);
    let _ = OUTERS[0].name;
}
