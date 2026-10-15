// audit 12 probe s1: const and static tables, aliases, tuples, lock statics written by helpers and dead code
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
use std::sync::{Mutex, RwLock};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
#[derive(Clone, Copy)]
struct Cfg { h: &'static Digest, legacy: &'static Digest }
struct Outer { inner: Cfg, n: u8 }
const BASE: Cfg = Cfg { h: &SHA384, legacy: &SHA1 };
const ALIAS: Cfg = BASE;
const CREF: &Cfg = &BASE;
static FIX: Cfg = Cfg { h: &SHA512, legacy: &SHA1 };
static SREF: &Cfg = &FIX;
static SREF2: &&Cfg = &SREF;
static TAB: [Cfg; 2] = [Cfg { h: &SHA256, legacy: &SHA1 }, Cfg { h: &SHA384, legacy: &SHA1 }];
static ELEM: &Cfg = &TAB[1];
static SLICE: &[Cfg] = &TAB;
static NEST: ((&Digest, &Digest), &Digest) = ((&SHA256, &SHA1), &SHA512);
const OUTERS: [Outer; 2] = [Outer { inner: Cfg { h: &SHA512, legacy: &SHA1 }, n: 0 }, Outer { inner: Cfg { h: &SHA256, legacy: &SHA1 }, n: 1 }];
static CFG: Mutex<Cfg> = Mutex::new(Cfg { h: &SHA256, legacy: &SHA1 });
static RW: RwLock<Cfg> = RwLock::new(Cfg { h: &SHA384, legacy: &SHA1 });
static DEADW: RwLock<&'static Digest> = RwLock::new(&SHA256);
static OUTER: Mutex<Outer> = Mutex::new(Outer { inner: Cfg { h: &SHA256, legacy: &SHA1 }, n: 0 });
fn set_cfg(m: &Mutex<Cfg>) { m.lock().unwrap().h = &SHA512; }
fn set_rw() { *RW.write().unwrap() = Cfg { h: &SHA256, legacy: &SHA1 }; }
fn dead() { *DEADW.write().unwrap() = &SHA256; }
fn set_outer() { OUTER.lock().unwrap().inner.h = &SHA384; }

fn main() {
    let d = arg(0).into_bytes();
    let i = arg(1).len() % 2;
    let _ = digest(ALIAS.h, &d);
    let _ = digest(CREF.h, &d);
    let _ = digest(SREF.h, &d);
    let _ = digest(SREF2.h, &d);
    let _ = digest(ELEM.h, &d);
    let _ = digest(SLICE[i].h, &d);
    let _ = digest(NEST.0.1, &d);
    let _ = digest((NEST.0).0, &d);
    let _ = digest(OUTERS[i].inner.h, &d);
    if i == 1 { set_cfg(&CFG); }
    let _ = digest(CFG.lock().unwrap().h, &d);
    if i == 0 { set_rw(); }
    let _ = digest(RW.read().unwrap().h, &d);
    let _ = digest(*DEADW.read().unwrap(), &d);
    set_outer();
    let _ = digest(OUTER.lock().unwrap().inner.h, &d);
    let _ = digest(OUTER.lock().unwrap().inner.legacy, &d);
    let local = [Cfg { h: &SHA512, legacy: &SHA1 }; 3];
    let _ = digest(local[i].h, &d);
    let lits = [BASE, FIX];
    let _ = digest(lits[i].h, &d);
    let _ = i;
}
