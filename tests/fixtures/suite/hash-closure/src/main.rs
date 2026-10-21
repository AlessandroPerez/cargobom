use ring::digest;

fn main() {
    let algs: [&'static digest::Algorithm; 2] = [&digest::SHA256, &digest::SHA1_FOR_LEGACY_USE_ONLY];
    let data = b"closure";
    let sizes: Vec<usize> = algs.iter().map(|a| digest::digest(a, data).as_ref().len()).collect();
    println!("{:?}", sizes);
}
