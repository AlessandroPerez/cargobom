use ring::digest;

static TABLE: [&digest::Algorithm; 2] = [&digest::SHA512_256, &digest::SHA1_FOR_LEGACY_USE_ONLY];

fn main() {
    let d = digest::digest(TABLE[0], b"table");
    println!("{}", d.as_ref().len());
}
