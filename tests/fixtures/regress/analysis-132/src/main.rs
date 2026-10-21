// audit 13 probe a17: a lock static handed to a helper in a body holding an async closure
use ring::digest::{digest, Algorithm as Digest, SHA256, SHA512};
use std::sync::Mutex;
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
struct C { h: &'static Digest }
static CFG: Mutex<C> = Mutex::new(C { h: &SHA256 });
fn set(m: &Mutex<C>) { m.lock().unwrap().h = &SHA512; }

fn main() {
    let d = arg(0).into_bytes();
    let f = async || { 1u8 };
    let _ = f;
    if arg(1).is_empty() { set(&CFG); }
    let _ = digest(CFG.lock().unwrap().h, &d);
}
