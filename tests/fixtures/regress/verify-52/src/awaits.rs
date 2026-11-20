//! An `async` block a function builds and awaits is cited where the function builds it,
//! whichever of the two the blocks of its state machine have first: awaited where it is written,
//! through a function that hands it back, and in parentheses. An `async` method awaited where it
//! is called is called on its receiver, not on what it returns (another type of the file). A
//! generic type's generic `async fn`, awaited on the line below its call's closing parenthesis
//! (shadowsocks's `ProxyClientStream::connect_with_opts_map(.., |s| { .. })`): that parenthesis
//! is no place its body is run from.

use std::future::Future;

use sha2::{Digest, Sha256, Sha384, Sha512, Sha512_256};

fn same<F: Future<Output = Vec<u8>>>(f: F) -> F {
    f
}

pub async fn direct(data: Vec<u8>) -> Vec<u8> {
    async move {
        let h = Sha384::digest(&data);
        h.to_vec()
    }
    .await
}

pub async fn through(data: Vec<u8>) -> Vec<u8> {
    same(async move { Sha512::digest(&data).to_vec() })
        .await
}

// (the parentheses are the point)
#[allow(unused_parens)]
pub async fn parenthesised(data: Vec<u8>) -> Vec<u8> {
    same(
        (async move {
            let h = Sha512_256::digest(&data);
            h.to_vec()
        }),
    )
    .await
}

pub struct Client(pub Vec<u8>);
pub struct Session(pub Vec<u8>);

impl Client {
    pub async fn connect(&self) -> Session {
        Session(Sha256::digest(&self.0).to_vec())
    }
}

pub async fn session(data: Vec<u8>) -> Vec<u8> {
    let c = Client(data);
    let s = c.connect().await;
    s.0
}

pub struct Stream<S>(pub S);

impl<S: AsRef<[u8]>> Stream<S> {
    fn handshake(data: &[u8]) -> Vec<u8> {
        Sha256::digest(data).to_vec()
    }

    pub async fn connect_map<F: FnOnce(Vec<u8>) -> S>(data: Vec<u8>, map: F) -> Stream<S> {
        Stream(map(Self::handshake(&data)))
    }
}

pub async fn remote(data: Vec<u8>) -> Vec<u8> {
    let stream = Stream::connect_map(data, |d| {
        d.into_iter().rev().collect::<Vec<u8>>()
    })
    .await;
    stream.0
}
