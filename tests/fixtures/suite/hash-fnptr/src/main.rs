use ring::digest;

type HashFn = fn(&'static digest::Algorithm, &[u8]) -> digest::Digest;

fn main() {
    let hash_fn: HashFn = digest::digest;
    let d = hash_fn(&digest::SHA512, b"pointer");
    println!("{}", d.as_ref().len());
}
