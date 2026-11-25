use sha2::{Digest, Sha256};
use std::marker::PhantomData;

struct Job<D>(Vec<u8>, PhantomData<D>);

impl<D: Digest> Job<D> {
    async fn run(self) -> Vec<u8> {
        D::digest(&self.0).to_vec()
    }
}

#[pm::launched]
fn start() -> Job<Sha256> {
    Job(
        std::env::args().next().unwrap_or_default().into_bytes(),
        PhantomData,
    )
}
