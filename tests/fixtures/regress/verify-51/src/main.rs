mod alias;
mod blocks;
mod defaults;
mod moved;
mod shown;

use std::future::Future;

use moved::Action as _;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

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
    let a = block_on(defaults::sign(&defaults::Bucket(input.clone())));
    let b = alias::Config::new().fingerprint(&input);
    let c = blocks::spawned(input.clone());
    let d = moved::Parse(input.clone()).execute();
    let e = shown::render(&input);
    println!("{:x?} {:x?} {:x?} {:x?} {e}", &a[..4], &b[..4], &c[..4], &d[..4]);
}
