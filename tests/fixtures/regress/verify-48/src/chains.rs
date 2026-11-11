//! oha: one generic `async fn` instantiated along two chains of callers. The occurrence lists
//! both; the second chain's first caller awaits the function the first chain started at.

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use sha2::{Digest, Sha512_256};

async fn lookup<D: Digest>(data: &[u8]) -> Vec<u8> {
    D::digest(data).to_vec()
}

async fn client<D: Digest>(data: &[u8]) -> Vec<u8> {
    let found = lookup::<D>(data).await;
    found
}

async fn http1(data: &[u8]) -> Vec<u8> {
    let (first, _) = (client::<Sha512_256>(data).await, 1);
    first
}

async fn http2(data: &[u8]) -> Vec<u8> {
    let stream = client::<Sha512_256>(data);
    stream.await
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

pub fn both(data: &[u8]) -> Vec<u8> {
    let mut out = block_on(http1(data));
    out.extend(block_on(http2(data)));
    out
}
