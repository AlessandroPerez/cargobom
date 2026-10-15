// round 14 regress (audit 13 verifier probe vo4): async code
use futures_executor::block_on;
use ring::digest::{digest, Algorithm, SHA256, SHA384, SHA512};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

struct Job { alg: &'static Algorithm }

async fn hash_with(alg: &'static Algorithm, d: Vec<u8>) -> usize {
    digest(alg, &d).as_ref().len()
}

async fn run(job: Job, d: Vec<u8>) -> usize {
    let n = hash_with(job.alg, d.clone()).await;
    let extra = async { digest(&SHA512, &d).as_ref().len() }.await;
    let alg = if n > 40 { &SHA384 } else { job.alg };
    let m = async move { digest(alg, &d).as_ref().len() };
    n + extra + m.await
}

fn main() {
    let d = arg(0).into_bytes();
    let job = Job { alg: &SHA256 };
    let _ = block_on(run(job, d));
}
