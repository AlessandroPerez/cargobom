// audit 13 probe a8: lock statics, constants, thread locals, holders and returned borrows of another crate of the workspace
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
use std::sync::Mutex;
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
static LOCAL: Mutex<clib::Cfg> = Mutex::new(clib::Cfg { h: &SHA256, legacy: &SHA1 });
const ALIAS: clib::Cfg = clib::BASE;
static MADE: clib::Cfg = clib::make();

fn main() {
    let d = arg(0).into_bytes();
    let i = arg(1).len() % 2;
    if i == 1 { clib::set_cfg(&clib::CFG); }
    let _ = digest(clib::CFG.lock().unwrap().h, &d);
    if i == 1 { clib::set_cfg(&LOCAL); }
    let _ = digest(LOCAL.lock().unwrap().h, &d);
    let _ = digest(ALIAS.h, &d);
    let _ = digest(MADE.h, &d);
    let _ = digest(clib::TL.get(), &d);
    let mut x1: &'static Digest = &SHA256;
    { let w = clib::wrap(&mut x1); *w.r = &SHA512; }
    let _ = digest(x1, &d);
    let mut s = clib::S { alg: &SHA256, other: &SHA1 };
    *s.slot() = &SHA384;
    let _ = digest(s.alg, &d);
    let _ = digest(s.other, &d);
    if i == 0 { clib::set_direct(); }
    let _ = digest(clib::CFG.lock().unwrap().legacy, &d);
}
