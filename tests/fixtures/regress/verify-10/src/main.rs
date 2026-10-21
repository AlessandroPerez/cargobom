// audit 10 probe vp7 (M11): closures on one line, and nested; a closure's instantiation detail
// cites the closure (its column) whose extent holds the code instantiated in it
use sha2::Digest;

fn run<F: Fn(&[u8]) -> usize>(f: F, d: &[u8]) -> usize {
    f(d)
}

fn run2<F: Fn(&[u8]) -> usize, G: Fn(&[u8]) -> usize>(f: F, g: G, d: &[u8]) -> usize {
    f(d) + g(d)
}

fn main() {
    let d = std::env::args().next().unwrap().into_bytes();
    let a = run2(|x| sha2::Sha256::digest(x).len(), |x| sha2::Sha384::digest(x).len(), &d);
    let b = run(
        |x| {
            run(
                |y| {
                    sha2::Sha512::digest(y).len()
                },
                x,
            )
        },
        &d,
    );
    let c = run(|x| sha2::Sha224::digest(x).len(), &d) + run(|x| sha2::Sha512_256::digest(x).len(), &d);
    println!("{}", a + b + c);
}
