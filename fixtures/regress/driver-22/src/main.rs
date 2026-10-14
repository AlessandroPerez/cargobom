// Values across functions (fifth audit round). Each case says which algorithm or key reaches
// the call; "one of N" lists every value the program stores in a field or passes for a
// parameter, flow-insensitively.
use std::cell::Cell;
use std::sync::{LazyLock, OnceLock, RwLock};

use aes_gcm::aead::KeyInit;
use aes_gcm::Aes256Gcm;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::digest::{digest, Algorithm, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};

// C1: a closure that captures a struct whole reads its field: the key is hard-coded (line 18),
// not the environment value of the other field
struct Cfg {
    key: [u8; 32],
    name: String,
}
fn c1() -> usize {
    let cfg = Cfg { key: [7u8; 32], name: std::env::var("NAME").unwrap_or_default() };
    let f = || cfg.name.len() + Aes256Gcm::new_from_slice(&cfg.key).is_ok() as usize;
    f()
}

// C2: an `async fn` and a closure using their function's parameter: AES-256-GCM from `main`,
// a hard-coded nonce
async fn c2_async(key: &LessSafeKey, buf: &mut Vec<u8>) {
    let _ = key.seal_in_place_append_tag(Nonce::assume_unique_for_key([2; 12]), Aad::empty(), buf);
}
fn c2_closure(key: &LessSafeKey, buf: &mut Vec<u8>) {
    let f = |b: &mut Vec<u8>| key.seal_in_place_append_tag(Nonce::assume_unique_for_key([3; 12]), Aad::empty(), b);
    let _ = f(buf);
}

// C3: a closure's parameters in order: SHA-256 at the first call, SHA-512 at the second
fn c3(d: &[u8]) -> usize {
    let f = |a: &'static Algorithm, b: &'static Algorithm| digest(a, d).as_ref().len() + digest(b, d).as_ref().len();
    f(&SHA256, &SHA512)
}

// C4: writes into a field other than a literal or an assignment: `mem::replace`, a function
// writing through `&mut`, a reference to the field, an element, a push. Each read is the
// value stored last on the way there: SHA-384, SHA-512, SHA-1 (`use_ctx`).
struct Ctx {
    alg: &'static Algorithm,
}
struct Multi {
    a: [&'static Algorithm; 1],
    v: Vec<&'static Algorithm>,
}
fn set_slot(slot: &mut &'static Algorithm) {
    *slot = &SHA512;
}
fn use_ctx(c: &Ctx, d: &[u8]) -> usize {
    digest(c.alg, d).as_ref().len()
}
fn use_multi(m: &Multi, d: &[u8]) -> usize {
    digest(m.a[0], d).as_ref().len() + digest(m.v[0], d).as_ref().len()
}
fn c4(d: &[u8]) -> usize {
    let mut c1 = Ctx { alg: &SHA256 };
    let _ = std::mem::replace(&mut c1.alg, &SHA384);
    let mut c2 = Ctx { alg: &SHA256 };
    set_slot(&mut c2.alg);
    let mut c3 = Ctx { alg: &SHA256 };
    let r = &mut c3.alg;
    *r = &SHA1;
    let mut m = Multi { a: [&SHA256], v: Vec::new() };
    m.a[0] = &SHA1;
    m.v.push(&SHA384);
    use_ctx(&c1, d) + use_ctx(&c2, d) + use_ctx(&c3, d) + use_multi(&m, d)
}

// C5: one generic struct, two instantiations: the digest gets SHA-256 only, the AEAD key
// AES-256-GCM only
struct Wrapper<T>(T);
fn use_digest(w: &Wrapper<&'static Algorithm>, d: &[u8]) -> usize {
    digest(w.0, d).as_ref().len()
}
fn use_aead(w: &Wrapper<&'static ring::aead::Algorithm>, k: &[u8]) -> bool {
    UnboundKey::new(w.0, k).is_ok()
}

// C6: statics written at run time: through a helper taking the lock (SHA-256 or SHA-1), a
// `LazyLock` of a function (SHA-384), `get_or_init` with a function (SHA-512), a
// `thread_local!` cell set later (SHA-256 or SHA-512)
static ALG: RwLock<&'static Algorithm> = RwLock::new(&SHA256);
fn set_alg(l: &RwLock<&'static Algorithm>, a: &'static Algorithm) {
    *l.write().unwrap() = a;
}
fn pick() -> &'static Algorithm {
    &SHA384
}
fn pick2() -> &'static Algorithm {
    &SHA512
}
static LZ: LazyLock<&'static Algorithm> = LazyLock::new(pick);
static OL: OnceLock<&'static Algorithm> = OnceLock::new();
thread_local! { static TA: Cell<&'static Algorithm> = Cell::new(&SHA256); }
fn c6(d: &[u8]) -> usize {
    set_alg(&ALG, &SHA1);
    if d.is_empty() {
        TA.set(&SHA512);
    }
    digest(*ALG.read().unwrap(), d).as_ref().len()
        + digest(*LZ, d).as_ref().len()
        + digest(OL.get_or_init(pick2), d).as_ref().len()
        + digest(TA.get(), d).as_ref().len()
}

// C7: a call through a function pointer made of the program's function: SHA-512
fn hash_with(a: &'static Algorithm, x: &[u8]) -> usize {
    digest(a, x).as_ref().len()
}
fn c7(d: &[u8]) -> usize {
    let f: fn(&'static Algorithm, &[u8]) -> usize = hash_with;
    f(&SHA512, d)
}

fn main() {
    let d = std::env::args().next().unwrap_or_default().into_bytes();
    let k = d.clone();
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &k).unwrap_or_else(|_| {
        UnboundKey::new(&AES_256_GCM, &[0; 32]).unwrap()
    }));
    let mut buf = d.clone();
    let w = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(w);
    let _ = std::pin::pin!(c2_async(&key, &mut buf)).as_mut().poll(&mut cx);
    c2_closure(&key, &mut buf);
    println!(
        "{} {} {} {} {} {} {}",
        c1(),
        c3(&d),
        c4(&d),
        use_digest(&Wrapper(&SHA256), &d),
        use_aead(&Wrapper(&AES_256_GCM), &k),
        c6(&d),
        c7(&d)
    );
}
