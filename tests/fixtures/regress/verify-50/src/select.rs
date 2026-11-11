//! rustic-rs (opendal's `tokio::select! { r = fut => .. }`): a future held by a variable is
//! polled in a closure a macro of another crate writes around its arguments. The closure is
//! cited where the invocation starts, and the future's body there too: the invocation uses the
//! variable.

use sha2::{Digest, Sha224};

async fn get(data: Vec<u8>) -> Vec<u8> {
    Sha224::digest(&data).to_vec()
}

pub async fn connect(data: &[u8]) -> Vec<u8> {
    let fut = get(data.to_vec());

    let (found,) = futures_util::join!(
        fut
    );
    found
}
