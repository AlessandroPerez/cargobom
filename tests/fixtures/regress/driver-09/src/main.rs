use ring::digest::{digest, Algorithm, SHA384, SHA512};

struct H;
impl H {
    const A: &'static Algorithm = &SHA384;
}

#[allow(dead_code)]
fn dead(d: &[u8]) -> usize {
    digest(H::A, d).as_ref().len()
}

#[allow(dead_code)]
fn dead2(d: &[u8]) -> usize {
    digest(const { &SHA512 }, d).as_ref().len()
}

include!("gen.rs");

fn main() {
    println!("{}", included(b"i"));
}

#[allow(dead_code)]
async fn af(d: &[u8]) -> usize {
    let f = digest;
    f(&SHA512, d).as_ref().len()
}
