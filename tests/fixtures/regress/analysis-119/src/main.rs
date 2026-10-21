// audit 13 probe a4: lock statics written by helpers, guards, lazies (H4, L1, L4 variations)
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
use std::sync::{LazyLock, Mutex, MutexGuard, OnceLock, RwLock};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
struct Cfg { h: &'static Digest, legacy: &'static Digest }
static R1: RwLock<Cfg> = RwLock::new(Cfg { h: &SHA256, legacy: &SHA1 });
fn set_rw(l: &RwLock<Cfg>) { l.write().unwrap().h = &SHA512; }
static M2: Mutex<Cfg> = Mutex::new(Cfg { h: &SHA256, legacy: &SHA1 });
fn set_guard(g: &mut MutexGuard<Cfg>) { g.h = &SHA384; }
static M3: Mutex<Cfg> = Mutex::new(Cfg { h: &SHA256, legacy: &SHA1 });
fn set_cfg(c: &mut Cfg) { c.h = &SHA512; }
static M4: Mutex<Cfg> = Mutex::new(Cfg { h: &SHA256, legacy: &SHA1 });
fn outer(m: &Mutex<Cfg>) { inner(m) }
fn inner(m: &Mutex<Cfg>) { m.lock().unwrap().h = &SHA384; }
static M5: Mutex<Cfg> = Mutex::new(Cfg { h: &SHA256, legacy: &SHA1 });
fn set_all(m: &Mutex<Cfg>) { *m.lock().unwrap() = Cfg { h: &SHA512, legacy: &SHA1 }; }
static M6: Mutex<&'static Digest> = Mutex::new(&SHA256);
fn set_ref(m: &Mutex<&'static Digest>) { *m.lock().unwrap() = &SHA384; }
static LZ: LazyLock<Mutex<Cfg>> = LazyLock::new(|| Mutex::new(Cfg { h: &SHA256, legacy: &SHA1 }));
fn set_lz(m: &Mutex<Cfg>) { m.lock().unwrap().h = &SHA512; }
static M7: Mutex<Cfg> = Mutex::new(Cfg { h: &SHA256, legacy: &SHA1 });
fn set_val(m: &Mutex<Cfg>, a: &'static Digest) { m.lock().unwrap().h = a; }
static M8: Mutex<Cfg> = Mutex::new(Cfg { h: &SHA256, legacy: &SHA1 });
fn set_if(m: &Mutex<Cfg>) { if let Ok(mut g) = m.lock() { g.h = &SHA384; } }
struct App { m: &'static Mutex<Cfg> }
static M9: Mutex<Cfg> = Mutex::new(Cfg { h: &SHA256, legacy: &SHA1 });
fn set_app(a: &App) { a.m.lock().unwrap().h = &SHA512; }
fn pick() -> &'static Digest { &SHA384 }
static LZF: LazyLock<&'static Digest> = LazyLock::new(pick);
static OL: OnceLock<Cfg> = OnceLock::new();
fn init(o: &OnceLock<Cfg>) { let _ = o.set(Cfg { h: &SHA512, legacy: &SHA1 }); }

fn main() {
    let d = arg(0).into_bytes();
    let i = arg(1).len() % 2;
    if i == 1 { set_rw(&R1); }
    let _ = digest(R1.read().unwrap().h, &d);
    if i == 1 { set_guard(&mut M2.lock().unwrap()); }
    let _ = digest(M2.lock().unwrap().h, &d);
    if i == 1 { set_cfg(&mut M3.lock().unwrap()); }
    let _ = digest(M3.lock().unwrap().h, &d);
    if i == 1 { outer(&M4); }
    let _ = digest(M4.lock().unwrap().h, &d);
    if i == 1 { set_all(&M5); }
    let _ = digest(M5.lock().unwrap().h, &d);
    if i == 1 { set_ref(&M6); }
    let _ = digest(*M6.lock().unwrap(), &d);
    if i == 1 { set_lz(&LZ); }
    let _ = digest(LZ.lock().unwrap().h, &d);
    if i == 1 { set_val(&M7, &SHA384); }
    let _ = digest(M7.lock().unwrap().h, &d);
    if i == 1 { set_if(&M8); }
    let _ = digest(M8.lock().unwrap().h, &d);
    if i == 1 { set_app(&App { m: &M9 }); }
    let _ = digest(M9.lock().unwrap().h, &d);
    let _ = digest(*LZF, &d);
    if i == 1 { init(&OL); }
    let _ = digest(OL.get().map(|c| c.h).unwrap_or(&SHA256), &d);
}
