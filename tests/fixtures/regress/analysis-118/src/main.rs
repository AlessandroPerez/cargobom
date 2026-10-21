// audit 13 probe a3: constants and statics of constants, const fns, tuples, arrays (H3 variations)
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
#[derive(Clone, Copy)]
struct Cfg { h: &'static Digest, legacy: &'static Digest }
const BASE: Cfg = Cfg { h: &SHA384, legacy: &SHA1 };
const FIX: Cfg = Cfg { h: &SHA512, legacy: &SHA1 };
const ALIAS: Cfg = BASE;
const ALIAS2: Cfg = ALIAS;
static S_ALIAS: Cfg = BASE;
const CREF2: &Cfg = &ALIAS;
const fn make() -> Cfg { Cfg { h: &SHA256, legacy: &SHA1 } }
const fn make2() -> Cfg { make() }
static MADE2: Cfg = make2();
const MADE_C: Cfg = make();
struct Table { rows: [Cfg; 2] }
static TAB: Table = Table { rows: [BASE, FIX] };
static TP: (Cfg, Cfg) = (BASE, FIX);
static UPD: Cfg = Cfg { h: &SHA256, ..BASE };
static AREF: [&Cfg; 2] = [&BASE, &FIX];
impl Cfg { const DEF: Cfg = BASE; }
struct Outer { inner: Cfg, n: u8 }
const NESTED2: Outer = Outer { inner: ALIAS, n: 0 };
static ST_OF_ST: &Cfg = &S_ALIAS;
const fn pick(i: usize) -> Cfg { if i == 0 { BASE } else { FIX } }
static PICKED: Cfg = pick(1);

fn main() {
    let d = arg(0).into_bytes();
    let i = arg(1).len() % 2;
    let _ = digest(ALIAS2.h, &d);
    let _ = digest(S_ALIAS.h, &d);
    let _ = digest(CREF2.h, &d);
    let _ = digest(MADE2.h, &d);
    let _ = digest(MADE_C.h, &d);
    let _ = digest(TAB.rows[i].h, &d);
    let _ = digest(TP.1.h, &d);
    let _ = digest(UPD.h, &d);
    let _ = digest(UPD.legacy, &d);
    let _ = digest(AREF[i].h, &d);
    let _ = digest(Cfg::DEF.h, &d);
    let _ = digest(NESTED2.inner.h, &d);
    let _ = digest(ST_OF_ST.h, &d);
    let _ = digest(PICKED.h, &d);
    let _ = digest(TP.0.legacy, &d);
}
