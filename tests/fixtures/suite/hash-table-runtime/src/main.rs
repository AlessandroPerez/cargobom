use ring::digest;

static TABLE: [&digest::Algorithm; 3] = [&digest::SHA256, &digest::SHA384, &digest::SHA512];

fn main() {
    let i = usize::from(std::env::args().count() > 1);
    let d = digest::digest(TABLE[i], b"table");
    println!("{} {}", i, d.as_ref().len());
}
