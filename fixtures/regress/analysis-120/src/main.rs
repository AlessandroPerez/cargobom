// audit 13 probe a5: thread_local! keys (H10 variations)
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
use std::cell::{Cell, RefCell};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
struct Cfg { h: &'static Digest, legacy: &'static Digest }
fn mk() -> Cfg { Cfg { h: &SHA384, legacy: &SHA1 } }
thread_local! {
    static LAZYT: RefCell<Cfg> = RefCell::new(Cfg { h: &SHA256, legacy: &SHA1 });
    static CELLT: Cell<&'static Digest> = const { Cell::new(&SHA512) };
    static FNT: RefCell<Cfg> = RefCell::new(mk());
    static WR: RefCell<Cfg> = const { RefCell::new(Cfg { h: &SHA256, legacy: &SHA1 }) };
}
mod inner { use super::*; thread_local! { pub static MODT: Cell<&'static Digest> = const { Cell::new(&SHA384) }; } }
fn via_helper() -> &'static Digest { LAZYT.with(|c| c.borrow().h) }
fn set_wr(c: &RefCell<Cfg>) { c.borrow_mut().h = &SHA512; }
fn local_key() -> &'static Digest {
    thread_local! { static INFN: Cell<&'static Digest> = const { Cell::new(&SHA256) }; }
    INFN.get()
}

fn main() {
    let d = arg(0).into_bytes();
    let i = arg(1).len() % 2;
    let a = LAZYT.with(|c| c.borrow().h);
    let _ = digest(a, &d);
    let _ = digest(CELLT.get(), &d);
    let b = FNT.with_borrow(|c| c.h);
    let _ = digest(b, &d);
    if i == 1 { WR.with(|c| set_wr(c)); }
    let w = WR.with_borrow(|c| c.h);
    let _ = digest(w, &d);
    let _ = digest(inner::MODT.get(), &d);
    let _ = digest(via_helper(), &d);
    let _ = digest(local_key(), &d);
    if i == 0 { CELLT.set(&SHA1); }
    let _ = digest(CELLT.with(|c| c.get()), &d);
}
