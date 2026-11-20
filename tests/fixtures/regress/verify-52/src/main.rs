#[macro_use]
mod hashing;
mod awaits;
mod coded;
mod derived;
mod held;
mod made;
mod oids;
mod wrapped;

use std::future::Future;
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
    let a = block_on(awaits::direct(input.clone()));
    let b = block_on(awaits::through(input.clone()));
    let c = block_on(awaits::parenthesised(input.clone()));
    let d = block_on(awaits::session(input.clone()));
    let e = block_on(held::sign(&input)).unwrap_or_default();
    let f = made::v1::id(&input);
    let g = made::v2::id(&input);
    let h = made::proof(&input);
    let i = derived::Record(input.clone()).fingerprint();
    let j = block_on(awaits::remote(input.clone()));
    let k = [oids::alpha(), oids::beta()].concat();
    let l = {
        use wrapped::Tagged as _;
        let third = wrapped::Third(input.clone()).tag_bytes();
        [wrapped::First(third).tag_bytes(), wrapped::Second(input.clone()).tag_bytes()].concat()
    };
    let m = {
        use coded::Coded as _;
        let code = coded::Code(input.len() as u8 % 4);
        code.clone().digest(&input)
    };
    println!("{} {}", oids::ALPHA, oids::BETA);
    for x in [a, b, c, d, e, f, g, h, i, j, k, l, m] {
        println!("{:x?}", &x[..4]);
    }
}
