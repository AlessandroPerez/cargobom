//! sccache (redis's cluster connection): the future an `async fn` made is held by a variable,
//! and boxed on a later line into the trait object that polls it. The function's body is cited
//! where the variable is used, not at the field of that name a line above.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use sha2::{Digest, Sha384};

struct Request {
    retries: u8,
    future: State,
}

enum State {
    Future {
        future: Pin<Box<dyn Future<Output = Vec<u8>>>>,
    },
}

async fn try_request(data: Vec<u8>) -> Vec<u8> {
    Sha384::digest(&data).to_vec()
}

pub fn handle(data: &[u8]) -> Vec<u8> {
    let future = try_request(data.to_vec());
    let mut request = Request {
        retries: 0,
        future: State::Future {
            future: Box::pin(future),
        },
    };
    let mut cx = Context::from_waker(Waker::noop());
    let State::Future { future } = &mut request.future;
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => vec![request.retries],
    }
}

pub fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}
