mod boxed;
mod guarded;
mod paired;
mod summed;
mod traced;

// Modules a macro's invocation declares, each in a file of its own (tokio's `cfg_rt! { mod
// task; }`, reqwest's `if_hyper! { mod async_impl; }`): the compiler has all a file holds as
// defined in that expansion, and the macro writes none of it.
macro_rules! gated {
    ($($item:item)*) => {
        $( $item )*
    };
}

gated! {
    mod loaded;
}

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use sha2::{Sha256, Sha512_256};

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
    let key = boxed::Key(input.clone());
    let a = block_on(key.sign(input.clone()));
    let b = traced::derive_key(&input);
    let c = traced::hash_with::<Sha256>(&input);
    let d = traced::hash_with::<Sha512_256>(&input);
    let e = summed::both(&input);
    let f = inner::tag(&input);
    let g = loaded::Reader(input.clone()).read();
    let h = block_on(guarded::checked(input.clone()));
    let i = paired::wide::once(&input);
    let j = paired::wide::twice(&input);
    let all = [a, b, c, d, e, f, g, h, i, j];
    println!("{}", all.iter().map(Vec::len).sum::<usize>());
}
