// audit 12 probe s2: consts and statics read by field in other shapes; lock statics written in other ways
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
use std::sync::{LazyLock, Mutex, OnceLock};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
#[derive(Clone, Copy)]
struct Cfg { h: &'static Digest, legacy: &'static Digest }
impl Cfg { const DEF: Cfg = Cfg { h: &SHA384, legacy: &SHA1 }; fn set(&mut self, a: &'static Digest) { self.h = a; } }
struct Outer { inner: Cfg }
const BASE: Cfg = Cfg { h: &SHA256, legacy: &SHA1 };
const NESTED: Outer = Outer { inner: BASE };
static FROM_CONST: Cfg = BASE;
static ARR: [Cfg; 2] = [BASE, Cfg { h: &SHA512, legacy: &SHA1 }];
const fn make() -> Cfg { Cfg { h: &SHA512, legacy: &SHA1 } }
static MADE: Cfg = make();
static TS: (Cfg, Cfg) = (Cfg { h: &SHA384, legacy: &SHA1 }, Cfg { h: &SHA512, legacy: &SHA1 });
const TUP: (&Digest, &Digest) = (&SHA256, &SHA1);
static LAZY: LazyLock<Cfg> = LazyLock::new(|| Cfg { h: &SHA512, legacy: &SHA1 });
static ONCE: OnceLock<Cfg> = OnceLock::new();
static M1: Mutex<Cfg> = Mutex::new(Cfg { h: &SHA256, legacy: &SHA1 });
static M2: Mutex<Cfg> = Mutex::new(Cfg { h: &SHA256, legacy: &SHA1 });
static M3: Mutex<Cfg> = Mutex::new(Cfg { h: &SHA256, legacy: &SHA1 });
static M4: Mutex<Cfg> = Mutex::new(Cfg { h: &SHA256, legacy: &SHA1 });

fn main() {
    let d = arg(0).into_bytes();
    let i = arg(1).len() % 2;
    let _ = digest(BASE.h, &d);
    let _ = digest(NESTED.inner.h, &d);
    let _ = digest(FROM_CONST.h, &d);
    let _ = digest(ARR[i].h, &d);
    let _ = digest(MADE.h, &d);
    let _ = digest(TS.1.h, &d);
    let _ = digest(TUP.1, &d);
    let _ = digest(Cfg::DEF.h, &d);
    let _ = digest(LAZY.h, &d);
    let _ = ONCE.set(Cfg { h: &SHA384, legacy: &SHA1 });
    let _ = digest(ONCE.get().unwrap().h, &d);
    { let mut g = M1.lock().unwrap(); g.h = &SHA512; }
    let _ = digest(M1.lock().unwrap().h, &d);
    *M2.lock().unwrap() = Cfg { h: &SHA384, legacy: &SHA1 };
    let _ = digest(M2.lock().unwrap().h, &d);
    M3.lock().unwrap().set(&SHA512);
    let _ = digest(M3.lock().unwrap().h, &d);
    let mut local = Cfg { h: &SHA384, legacy: &SHA1 };
    std::mem::swap(&mut *M4.lock().unwrap(), &mut local);
    let _ = digest(M4.lock().unwrap().h, &d);
    let _ = digest(local.h, &d);
}
