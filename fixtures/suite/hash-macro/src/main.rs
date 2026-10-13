use ring::digest;

macro_rules! fingerprint {
    ($alg:expr, $data:expr) => {
        digest::digest($alg, $data).as_ref().to_vec()
    };
}

fn main() {
    let a = fingerprint!(&digest::SHA256, b"macro one");
    let b = fingerprint!(&digest::SHA384, b"macro two");
    println!("{} {}", a.len(), b.len());
}
