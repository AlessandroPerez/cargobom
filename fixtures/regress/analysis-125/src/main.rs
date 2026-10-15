// audit 13 probe a10: lock statics reached through accessors, closures, generic helpers, struct fields (H4 variations); one struct type per static
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
use std::sync::Mutex;
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
struct C1 { h: &'static Digest }
struct C2 { h: &'static Digest }
struct C3 { h: &'static Digest }
struct C4 { h: &'static Digest }
struct C5 { h: &'static Digest, legacy: &'static Digest }
static M1: Mutex<C1> = Mutex::new(C1 { h: &SHA256 });
fn m1() -> &'static Mutex<C1> { &M1 }
fn set1(m: &Mutex<C1>) { m.lock().unwrap().h = &SHA512; }
static M2: Mutex<C2> = Mutex::new(C2 { h: &SHA256 });
static M3: Mutex<C3> = Mutex::new(C3 { h: &SHA256 });
trait Store { fn put(&self, a: &'static Digest); }
impl Store for Mutex<C3> { fn put(&self, a: &'static Digest) { self.lock().unwrap().h = a; } }
static M4: Mutex<C4> = Mutex::new(C4 { h: &SHA256 });
fn set4<M: std::ops::Deref<Target = Mutex<C4>>>(m: M) { m.lock().unwrap().h = &SHA384; }
static M5: Mutex<C5> = Mutex::new(C5 { h: &SHA256, legacy: &SHA1 });
fn set5(m: &Mutex<C5>) { let mut g = m.lock().unwrap(); g.h = &SHA512; g.legacy = &SHA384; }

fn main() {
    let d = arg(0).into_bytes();
    let i = arg(1).len() % 2;
    if i == 1 { set1(m1()); }
    let _ = digest(M1.lock().unwrap().h, &d);
    let set2 = |m: &Mutex<C2>| m.lock().unwrap().h = &SHA384;
    if i == 1 { set2(&M2); }
    let _ = digest(M2.lock().unwrap().h, &d);
    if i == 1 { M3.put(&SHA512); }
    let _ = digest(M3.lock().unwrap().h, &d);
    if i == 1 { set4(&M4); }
    let _ = digest(M4.lock().unwrap().h, &d);
    if i == 1 { set5(&M5); }
    let _ = digest(M5.lock().unwrap().h, &d);
    let _ = digest(M5.lock().unwrap().legacy, &d);
}
