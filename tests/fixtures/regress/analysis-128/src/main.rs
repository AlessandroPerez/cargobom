// audit 13 probe a13: cursor loops (pointer cycles) beside an unrelated lent variable; a helper writing two fields through one guard
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
use std::sync::Mutex;
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
struct Node { v: u8, next: Option<Box<Node>> }
struct C6 { h: &'static Digest, legacy: &'static Digest }
static M6: Mutex<C6> = Mutex::new(C6 { h: &SHA256, legacy: &SHA1 });
fn set6(m: &Mutex<C6>) { let mut g = m.lock().unwrap(); g.legacy = &SHA384; }
struct C7 { h: &'static Digest, legacy: &'static Digest }
static M7: Mutex<C7> = Mutex::new(C7 { h: &SHA256, legacy: &SHA1 });
fn set7(m: &Mutex<C7>) { let mut g = m.lock().unwrap(); g.h = &SHA512; g.legacy = &SHA384; }

fn main() {
    let d = arg(0).into_bytes();
    let i = arg(1).len() % 2;
    let mut b: &'static Digest = &SHA384;
    let rb = &mut b;
    let _ = rb.output_len();
    let mut list = Node { v: 0, next: Some(Box::new(Node { v: 1, next: None })) };
    let mut cur = &mut list;
    while let Some(n) = cur.next.as_mut() { n.v += 1; cur = n; }
    cur.v = 9;
    let _ = digest(b, &d);
    let mut a: &'static Digest = &SHA256;
    {
        let mut c = &mut a;
        for _ in 0..3 { let n = &mut *c; c = n; }
        *c = &SHA512;
    }
    let _ = digest(a, &d);
    if i == 1 { set6(&M6); }
    let _ = digest(M6.lock().unwrap().legacy, &d);
    if i == 1 { set7(&M7); }
    let _ = digest(M7.lock().unwrap().h, &d);
    let _ = digest(M7.lock().unwrap().legacy, &d);
}
