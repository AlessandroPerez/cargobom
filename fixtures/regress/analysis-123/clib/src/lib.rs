use ring::digest::{Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
use std::sync::Mutex;
use std::cell::Cell;
pub struct Cfg { pub h: &'static Digest, pub legacy: &'static Digest }
pub static CFG: Mutex<Cfg> = Mutex::new(Cfg { h: &SHA256, legacy: &SHA1 });
pub fn set_cfg(m: &Mutex<Cfg>) { m.lock().unwrap().h = &SHA512; }
pub fn set_direct() { CFG.lock().unwrap().h = &SHA384; }
pub const BASE: Cfg = Cfg { h: &SHA384, legacy: &SHA1 };
pub const fn make() -> Cfg { Cfg { h: &SHA512, legacy: &SHA1 } }
thread_local! { pub static TL: Cell<&'static Digest> = const { Cell::new(&SHA384) }; }
pub struct W<'a> { pub r: &'a mut &'static Digest }
pub fn wrap<'a>(x: &'a mut &'static Digest) -> W<'a> { W { r: x } }
pub struct S { pub alg: &'static Digest, pub other: &'static Digest }
impl S { pub fn slot(&mut self) -> &mut &'static Digest { &mut self.alg } }
