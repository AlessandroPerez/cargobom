use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

pub trait HasAlg {
    const ALG: &'static ring::digest::Algorithm;
}

pub struct Long;

impl HasAlg for Long {
    const ALG: &'static ring::digest::Algorithm = &ring::digest::SHA512;
}

// The closure hands a crypto call a slice the coroutine holds as a constant of its own (s3s's
// `verify_with_raw_path_fallback(.., || create_canonical_request_with_raw_uri_path(.., qs, ..))`
// with `qs` an empty slice).
async fn fed(d: &[u8]) -> Vec<u8> {
    let alg = &ring::digest::SHA256;
    let extra: &[u8] = &[];
    let hash = move || {
        let mut c = ring::digest::Context::new(alg);
        c.update(d);
        c.update(extra);
        c.finish().as_ref().to_vec()
    };
    hash()
}

// The closure's algorithm is one of a table the coroutine holds as a constant of its own.
async fn pick(i: usize, d: &[u8]) -> Vec<u8> {
    let algs = &[&ring::digest::SHA256, &ring::digest::SHA384];
    let hash = move |d: &[u8]| ring::digest::digest(algs[i], d).as_ref().to_vec();
    hash(d)
}

// A closure in a closure, the outer one holding the table.
fn nested(i: usize, d: &[u8]) -> Vec<u8> {
    let outer = move || {
        let algs = &[&ring::digest::SHA512_256, &ring::digest::SHA1_FOR_LEGACY_USE_ONLY];
        let hash = move |d: &[u8]| ring::digest::digest(algs[i], d).as_ref().to_vec();
        hash(d)
    };
    outer()
}

// In a generic `async fn`: the constant is the type parameter's, which the closure shares.
async fn typed<T: HasAlg>(d: &[u8]) -> Vec<u8> {
    let alg = T::ALG;
    let hash = move |d: &[u8]| ring::digest::digest(alg, d).as_ref().to_vec();
    hash(d)
}

fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

fn main() {
    let input = std::env::args().nth(1).unwrap_or_default().into_bytes();
    let i = input.len() % 2;
    let n = block_on(fed(&input)).len()
        + block_on(pick(i, &input)).len()
        + nested(i, &input).len()
        + block_on(typed::<Long>(&input)).len();
    println!("{n}");
}
