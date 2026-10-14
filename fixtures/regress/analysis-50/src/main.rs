// audit 9 probe p1: calls through function pointers held in consts, statics, containers, closures
use ring::digest::{self, Algorithm as Digest, Digest as Out, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512, SHA512_256};
use std::collections::HashMap;

type HashFn = fn(&'static Digest, &[u8]) -> Out;
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

const HF: HashFn = digest::digest;
static FNS: [HashFn; 2] = [digest::digest, digest::digest];
struct Holder { f: HashFn }
static HOLD: Holder = Holder { f: digest::digest };
static A: HashFn = digest::digest;
static B: &HashFn = &A;
fn my(a: &'static Digest, d: &[u8]) -> Out { digest::digest(a, d) } // SHA-384, SHA-512, SHA-1
static MY: HashFn = my;
fn twice(f: HashFn, d: &[u8]) -> Out { f(&SHA512_256, d) } // SHA-512/256 (digest::digest), and my's

fn main() {
    let d = arg(0).into_bytes();
    let _ = HF(&SHA256, &d); // SHA-256
    let _ = FNS[arg(1).len() % 2](&SHA384, &d); // SHA-384
    let _ = (HOLD.f)(&SHA512, &d); // SHA-512
    let _ = (*B)(&SHA1, &d); // SHA-1
    let mk = || digest::digest as HashFn;
    let _ = mk()(&SHA256, &d); // SHA-256
    let mut m: HashMap<u8, HashFn> = HashMap::new();
    m.insert(1, digest::digest);
    let _ = m[&1](&SHA512_256, &d); // SHA-512/256
    let _ = MY(&SHA384, &d); // my: SHA-384
    let b: Box<dyn Fn(&'static Digest, &[u8]) -> Out> = Box::new(digest::digest);
    let _ = b(&SHA1, &d); // SHA-1
    let v: Vec<HashFn> = vec![my];
    let _ = v[0](&SHA512, &d); // my: SHA-512
    let o: Option<HashFn> = Some(digest::digest);
    if let Some(f) = o { let _ = f(&SHA384, &d); } // SHA-384
    let _ = twice(digest::digest, &d);
    let _ = twice(my, &d);
    let _ = my(&SHA1, &d);
}
