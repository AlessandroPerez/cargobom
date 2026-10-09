// Argument origins and the walk (third audit round).
use std::future::Future;
use std::io::Read;
use std::sync::{LazyLock, Mutex};

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::KeyInit;
use rand::RngCore;

fn env_key() -> [u8; 32] {
    std::env::var("APP_KEY").unwrap().into_bytes()[..32]
        .try_into()
        .unwrap()
}

// D1: a key read from a file with `read_exact` (`Read` is defined in `alloc::io` on the pinned
// nightly): from a file, not the zeros it was initialized with
fn d1() -> bool {
    let mut key = [0u8; 32];
    std::fs::File::open("/etc/app/key")
        .unwrap()
        .read_exact(&mut key)
        .unwrap();
    Aes256Gcm::new_from_slice(&key).is_ok()
}

// D2: filled before an `.await` and used after it: random
async fn d2() -> bool {
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    std::future::ready(()).await;
    Aes256Gcm::new_from_slice(&key).is_ok()
}

// D3: filled inside a closure that captures it: random
fn d3() -> bool {
    let mut key = [0u8; 32];
    let mut seal = || {
        rand::rngs::OsRng.fill_bytes(&mut key);
        Aes256Gcm::new_from_slice(&key).is_ok()
    };
    seal()
}

// D4: one field of a struct literal filled afterwards: random, not the literal's zeros
struct Cfg {
    key: [u8; 32],
    rounds: u32,
}

fn d4() -> bool {
    let mut cfg = Cfg {
        key: [0u8; 32],
        rounds: 1,
    };
    rand::rngs::OsRng.fill_bytes(&mut cfg.key);
    Aes256Gcm::new_from_slice(&cfg.key).is_ok() && cfg.rounds == 1
}

// D5: filled chunk by chunk through `chunks_mut`: written through a borrow, not hard-coded
fn d5() -> bool {
    let mut key = [0u8; 32];
    for chunk in key.chunks_mut(16) {
        rand::rngs::OsRng.fill_bytes(chunk);
    }
    Aes256Gcm::new_from_slice(&key).is_ok()
}

// D6: filled through a lock guard: the lock's run-time contents, not hard-coded
fn d6() -> bool {
    let key = Mutex::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut *key.lock().unwrap());
    let k = *key.lock().unwrap();
    Aes256Gcm::new_from_slice(&k).is_ok()
}

// D7: an environment key replaced with a constant by `mem::replace`: hard-coded
fn d7() -> bool {
    let mut key = std::env::var("APP_KEY").unwrap().into_bytes();
    let _old = std::mem::replace(&mut key, b"0123456789abcdef0123456789abcdef".to_vec());
    Aes256Gcm::new_from_slice(&key).is_ok()
}

// D8: array destructuring: the first element is the environment key, not the literal beside it
fn d8() -> bool {
    let [live, _test] = [env_key(), [7u8; 32]];
    Aes256Gcm::new_from_slice(&live).is_ok()
}

// D9: half of an environment key overwritten with zeros: made of both
fn d9() -> bool {
    let mut key = env_key();
    key[..16].copy_from_slice(&[0u8; 16]);
    Aes256Gcm::new_from_slice(&key).is_ok()
}

// D10: the output slice that reaches PBKDF2 is the 32-byte one (its last definition)
#[allow(unused_assignments)]
fn d10() -> bool {
    let pw = std::env::var("PW").unwrap();
    let mut long = [0u8; 64];
    let mut short = [0u8; 32];
    let mut out: &mut [u8] = &mut long;
    if pw.is_empty() {
        out = &mut short;
    }
    out = &mut short;
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pw.as_bytes(), b"salt-salt-salt", 600_000, out);
    long[0] == short[0]
}

// D11: the program's own `fill` (not the standard library's): what it writes is a constant
fn fill(buf: &mut [u8]) {
    buf.copy_from_slice(b"0123456789abcdef0123456789abcdef");
}

fn d11() -> bool {
    let mut key = [0u8; 32];
    fill(&mut key);
    Aes256Gcm::new_from_slice(&key).is_ok()
}

// D12: an async closure (whose type rustc_public cannot convert): the function is still
// analysed, the digest before it and the cipher after it found
fn d12() -> bool {
    use sha2::Digest;
    let h = sha2::Sha256::digest(b"before");
    let f = async || 1u8;
    let _fut = f();
    let k = std::env::var("K").unwrap().into_bytes();
    Aes256Gcm::new_from_slice(&k).is_ok() && h.len() == 32
}

// D13: a knowledge-base function held in an `Option` and called through it
fn d13() -> bool {
    let d = std::env::args().next().unwrap().into_bytes();
    let hasher = Some(blake3::hash);
    hasher.map(|h| h(&d)).is_some()
}

// D14: a knowledge-base function in a static function pointer
static HASH: fn(&[u8]) -> blake3::Hash = blake3::hash;

fn d14() -> bool {
    let d = std::env::args().next().unwrap().into_bytes();
    HASH(&d).as_bytes()[0] == 0
}

// D15: a key in a `LazyLock` initialized from the environment: not hard-coded
static KEY: LazyLock<Vec<u8>> =
    LazyLock::new(|| std::env::var("APP_KEY").unwrap().into_bytes());

fn d15() -> bool {
    Aes256Gcm::new_from_slice(&KEY).is_ok()
}

// D16: a loop walking a linked list (`q = (*q).next`, once_cell's waiter queue): the search for
// the key's origin reads a longer path at each turn, and must end (it overflowed the stack)
struct Node {
    next: *const Node,
    key: [u8; 32],
}

fn d16(mut q: *const Node) -> bool {
    let mut last = [0u8; 32];
    unsafe {
        while !q.is_null() {
            last = (*q).key;
            q = (*q).next;
        }
    }
    Aes256Gcm::new_from_slice(&last).is_ok()
}

fn main() {
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    let _ = std::pin::pin!(d2()).poll(&mut cx);
    let n = Node {
        next: std::ptr::null(),
        key: env_key(),
    };
    println!(
        "{:?}",
        [
            d1(),
            d3(),
            d4(),
            d5(),
            d6(),
            d7(),
            d8(),
            d9(),
            d10(),
            d11(),
            d12(),
            d13(),
            d14(),
            d15(),
            d16(&n),
        ]
    );
}
