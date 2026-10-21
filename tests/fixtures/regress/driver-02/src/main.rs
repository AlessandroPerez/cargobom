use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{KeyInit, OsRng};
use aes_gcm::Aes256Gcm;
use ring::aead::Nonce;

// O1: a closure captures a hard-coded key from the enclosing function
fn o1(msgs: &[&[u8]]) -> usize {
    let key = [7u8; 32];
    msgs.iter()
        .map(|m| {
            let _c = Aes256Gcm::new_from_slice(&key).unwrap();
            m.len()
        })
        .sum()
}

// O2: a closure's own parameter
fn o2() -> usize {
    let f = |k: &[u8]| Aes256Gcm::new_from_slice(k).is_ok() as usize;
    f(&std::env::args().next().unwrap().into_bytes())
}

// O3: async fn, hard-coded key held across an await point
async fn o3() -> bool {
    let key = [9u8; 32];
    std::future::ready(()).await;
    Aes256Gcm::new_from_slice(&key).is_ok()
}

// O4: struct literal: the key comes from the environment, another field is a constant
struct Cfg {
    key: Vec<u8>,
    rounds: u32,
}
fn o4() -> bool {
    let cfg = Cfg { key: std::env::var("K").unwrap().into_bytes(), rounds: 100_000 };
    Aes256Gcm::new_from_slice(&cfg.key).is_ok() && cfg.rounds > 0
}

// O5: nonce filled by the RNG through a slice
fn o5() -> Nonce {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce[..]);
    Nonce::assume_unique_for_key(nonce)
}

// O6: hard-coded key, later mutated (after the crypto call)
fn o6() -> bool {
    let mut key = [7u8; 32];
    let ok = Aes256Gcm::new_from_slice(&key).is_ok();
    key.fill(0);
    ok
}

// O7: hard-coded key written through a reference
fn o7() -> bool {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let r = &mut key;
    *r = [7u8; 32];
    Aes256Gcm::new_from_slice(&key).is_ok()
}

// O8: hard-coded key assigned to the parameter
fn o8(mut key: [u8; 32], test: bool) -> bool {
    if test {
        key = [1u8; 32];
    }
    Aes256Gcm::new_from_slice(&key).is_ok()
}

// O9: five definitions, the fifth one hard-coded
fn o9(a: &[u8], b: &[u8], c: &[u8], d: &[u8], sel: u8) -> bool {
    let k: &[u8] = match sel {
        0 => a,
        1 => b,
        2 => c,
        3 => d,
        _ => b"0123456789abcdef0123456789abcdef",
    };
    Aes256Gcm::new_from_slice(k).is_ok()
}

// O10: nonce from a by-value unit-struct RNG argument (ZST)
fn o10() -> usize {
    use aes_gcm::aead::AeadCore;
    Aes256Gcm::generate_nonce(OsRng).len()
}

fn main() {
    let w = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(w);
    let mut f = std::pin::pin!(o3());
    let _ = f.as_mut().poll(&mut cx);
    let k = [3u8; 32];
    println!("{} {} {} {:?} {} {} {} {} {}", o1(&[b"x"]), o2(), o4(), o5().as_ref(), o6(), o7(), o8(k, false), o9(b"", b"", b"", b"", 4), o10());
}
use std::future::Future;

// O11: a realistic key-loading chain from the environment
#[allow(dead_code)]
fn o11() -> bool {
    let hex = std::env::var("KEY_HEX").expect("KEY_HEX");
    let bytes: Vec<u8> = hex.bytes().map(|b| b.wrapping_sub(b'0')).collect();
    let key: [u8; 32] = bytes[..32].try_into().unwrap();
    Aes256Gcm::new_from_slice(&key).is_ok()
}
