// audit 13 probe a16: a lock static passed to a live helper only by dead code
use ring::digest::{digest, Algorithm as Digest, SHA256, SHA384, SHA512};
use std::sync::Mutex;
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
struct C { h: &'static Digest }
static LIVE: Mutex<C> = Mutex::new(C { h: &SHA256 });
static DEAD: Mutex<C> = Mutex::new(C { h: &SHA384 });
fn set(m: &Mutex<C>) { m.lock().unwrap().h = &SHA512; }
#[allow(dead_code)]
fn never() { set(&DEAD); }

fn main() {
    let d = arg(0).into_bytes();
    if arg(1).is_empty() { set(&LIVE); }
    let _ = digest(LIVE.lock().unwrap().h, &d);
    let _ = digest(DEAD.lock().unwrap().h, &d);
}
