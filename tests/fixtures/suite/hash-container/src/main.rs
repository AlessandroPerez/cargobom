use ring::digest;

fn main() {
    let mut algs: Vec<&'static digest::Algorithm> = Vec::new();
    algs.push(&digest::SHA256);
    algs.push(&digest::SHA512);
    let small = digest::digest(algs[0], b"vec");
    let large = digest::digest(algs[1], b"vec");
    println!("{} {}", small.as_ref().len(), large.as_ref().len());
}
