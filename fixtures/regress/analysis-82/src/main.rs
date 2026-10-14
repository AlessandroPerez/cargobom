// round 12 regress (audit 11 probe st2): statics whose contents change at run time (writes only in dead code, OnceLock, Mutex of a struct), statics of statics
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
use std::sync::{Mutex, OnceLock, RwLock};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

static ALG: RwLock<&'static Digest> = RwLock::new(&SHA256);
#[allow(dead_code)]
fn dead() { *ALG.write().unwrap() = &SHA1; }
static ONCE: OnceLock<&'static Digest> = OnceLock::new();
struct Cfg { h: &'static Digest, legacy: &'static Digest }
static CFG: Mutex<Cfg> = Mutex::new(Cfg { h: &SHA384, legacy: &SHA1 });
static FIX: Cfg = Cfg { h: &SHA512, legacy: &SHA1 };
static REF: &Cfg = &FIX;

fn main() {
    let d = arg(0).into_bytes();
    let _ = digest(*ALG.read().unwrap(), &d);
    ONCE.get_or_init(|| &SHA384);
    let _ = digest(ONCE.get().unwrap(), &d);
    if arg(1).is_empty() { CFG.lock().unwrap().h = &SHA512; }
    let _ = digest(CFG.lock().unwrap().h, &d);
    let _ = digest(CFG.lock().unwrap().legacy, &d);
    let _ = digest(REF.h, &d);
    let _ = digest(REF.legacy, &d);
}
