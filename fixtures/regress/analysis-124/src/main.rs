// audit 13 probe a9: arrays of references to statics and constants; thread-local Cell shapes (H3, H10 variations)
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
use std::cell::{Cell, RefCell};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
struct Cfg { h: &'static Digest, legacy: &'static Digest }
static S1: Cfg = Cfg { h: &SHA384, legacy: &SHA1 };
static S2: Cfg = Cfg { h: &SHA512, legacy: &SHA1 };
static AREF2: [&Cfg; 2] = [&S1, &S2];
const C1: Cfg = Cfg { h: &SHA384, legacy: &SHA1 };
const C2: Cfg = Cfg { h: &SHA512, legacy: &SHA1 };
static AREF3: &[&Cfg] = &[&C1, &C2];
static NAMED: [(&str, &Cfg); 2] = [("a", &S1), ("b", &S2)];
thread_local! {
    static CK: Cell<&'static Digest> = const { Cell::new(&SHA256) };
    static CN: Cell<&'static Digest> = Cell::new(&SHA384);
    static RK: RefCell<&'static Digest> = const { RefCell::new(&SHA512) };
    static CS: Cell<&'static Digest> = const { Cell::new(&SHA256) };
}

fn main() {
    let d = arg(0).into_bytes();
    let i = arg(1).len() % 2;
    let _ = digest(AREF2[i].h, &d);
    let _ = digest(AREF3[i].h, &d);
    let _ = digest(NAMED[i].1.h, &d);
    let _ = digest(CK.get(), &d);
    let _ = digest(CK.with(|c| c.get()), &d);
    let _ = digest(CN.get(), &d);
    let _ = digest(RK.with(|c| *c.borrow()), &d);
    if i == 1 { CS.set(&SHA384); }
    let _ = digest(CS.get(), &d);
}
