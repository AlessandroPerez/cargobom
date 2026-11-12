//! ntpd (`SourceTask::spawn`): a parenthesised `async` block handed to a function that runs it,
//! which the compiler cites at its parenthesis; a closure handed to a call is cited at its own
//! `|`, not at the call's parenthesis.

use std::future::Future;

use sha2::{Digest, Sha224};

fn spawn<F: Future<Output = Vec<u8>>>(f: F) -> Vec<u8> {
    crate::block_on(f)
}

// (the parentheses are the point)
#[allow(unused_parens)]
pub fn spawned(data: Vec<u8>) -> Vec<u8> {
    spawn(
        (async move {
            let h = Sha224::digest(&data);
            h.to_vec()
        }),
    )
    .into_iter()
    .map(|b| Sha224::digest([b])[0])
    .collect()
}
