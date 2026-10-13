use ring::digest;
use std::sync::LazyLock;

static PRIMARY: &digest::Algorithm = &digest::SHA256;
static ARCHIVE: LazyLock<&'static digest::Algorithm> = LazyLock::new(|| &digest::SHA512);

fn main() {
    let a = digest::digest(PRIMARY, b"static");
    let b = digest::digest(*ARCHIVE, b"lazy");
    println!("{} {}", a.as_ref().len(), b.as_ref().len());
}
