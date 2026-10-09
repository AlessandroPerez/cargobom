// Code a derive generates with an input token's span (fourth audit round): SHA-512 is cited at
// the `#[derive(pm::HashField)]`, tagged `[derive ..]`, not at the field `key` whose span the
// derive gave it. And an `async` closure passed to a generic function: its type is one
// `rustc_public` cannot convert, a known limit that is not counted as a driver error.
use sha2::{Digest, Sha384};
use std::future::Future;
use std::task::{Context, Poll, Waker};

#[derive(pm::HashField)]
struct Secret {
    key: Vec<u8>,
}

async fn apply<F: AsyncFn(&[u8]) -> usize>(f: F) -> usize {
    f(b"y").await
}

fn main() {
    let s = Secret { key: vec![1, 2, 3] };
    let _ = s.digest_key();
    let tag = 3usize;
    let mut fut = std::pin::pin!(apply(async move |d: &[u8]| Sha384::digest(d).len() + tag));
    let mut cx = Context::from_waker(Waker::noop());
    while let Poll::Pending = fut.as_mut().poll(&mut cx) {}
}
