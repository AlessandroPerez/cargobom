// audit 7 probe: rand 0.4, a version the knowledge base does not cover
use rand::Rng;

fn main() {
    let a: u64 = rand::random();
    let mut r = rand::thread_rng();
    let b: u32 = r.gen();
    let mut buf = [0u8; 16];
    r.fill_bytes(&mut buf);
    let mut o = rand::OsRng::new().unwrap();
    o.fill_bytes(&mut buf);
    println!("{a} {b} {buf:?}");
}
