use ring::digest::{digest, SHA256, SHA384, SHA512};
use std::sync::LazyLock;

// T1: thread_local! with a crypto initializer
thread_local! {
    static TL: usize = digest(&SHA384, b"tl").as_ref().len();
}

// T2: an inline const block naming a static
fn t2(d: &[u8]) -> usize {
    let alg = const { &SHA256 };
    digest(alg, d).as_ref().len()
}

// T3: LazyLock in a static
static LAZY: LazyLock<usize> = LazyLock::new(|| digest(&SHA512, b"lazy").as_ref().len());

fn main() {
    let a = TL.with(|v| *v);
    println!("{} {} {}", a, t2(b"x"), *LAZY);
}
