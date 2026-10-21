// audit 12 probe s3: values a live writer puts in a static, fed by live and dead callers
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
use std::sync::{Mutex, RwLock};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
static ALG: RwLock<&'static Digest> = RwLock::new(&SHA256);
fn set_alg(a: &'static Digest) { *ALG.write().unwrap() = a; }
#[allow(dead_code)]
fn dead() { set_alg(&SHA1); }
struct Cfg { h: &'static Digest }
static CFG: Mutex<Cfg> = Mutex::new(Cfg { h: &SHA256 });
fn set_h(a: &'static Digest) { CFG.lock().unwrap().h = a; }
#[allow(dead_code)]
fn dead2() { set_h(&SHA512); }

fn main() {
    let d = arg(0).into_bytes();
    set_alg(&SHA384);
    let _ = digest(*ALG.read().unwrap(), &d);
    set_h(&SHA384);
    let _ = digest(CFG.lock().unwrap().h, &d);
}
