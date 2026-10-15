// round 14 regress (audit 13 verifier probe vt2): constants projected through fields
use ring::digest::{digest, Algorithm, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

#[derive(Clone, Copy)]
struct Cfg { h: &'static Algorithm, l: &'static Algorithm }
struct Outer { inner: Cfg, alt: Cfg }
const BASE: Cfg = Cfg { h: &SHA256, l: &SHA1 };
const B2: Cfg = Cfg { h: &SHA384, ..BASE };
const ALIAS: Cfg = B2;
const REF: &Cfg = &B2;
const fn make(x: &'static Algorithm) -> Cfg { Cfg { h: x, l: &SHA1 } }
static MADE: Cfg = make(&SHA512);
const OUT: Outer = Outer { inner: BASE, alt: B2 };
const TUP: (Cfg, (&Algorithm, &Algorithm)) = (BASE, (&SHA512, &SHA384));
static ARR: [Cfg; 2] = [B2, Cfg { h: &SHA512, l: &SHA1 }];

fn main() {
    let d = arg(0).into_bytes();
    let i = arg(1).len() % 2;
    let _ = digest(B2.h, &d);
    let _ = digest(B2.l, &d);
    let _ = digest(ALIAS.h, &d);
    let _ = digest(REF.l, &d);
    let _ = digest(MADE.h, &d);
    let _ = digest(MADE.l, &d);
    let _ = digest(OUT.inner.h, &d);
    let _ = digest(OUT.alt.h, &d);
    let _ = digest(TUP.0.h, &d);
    let _ = digest(TUP.1.1, &d);
    let _ = digest(ARR[i].h, &d);
    let _ = digest(ARR[i].l, &d);
}
