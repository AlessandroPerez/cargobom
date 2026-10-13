// Statics initialised on first use by macros and crates outside the standard library (fifth
// audit round): `lazy_static!` (SHA-384, its `Deref` reads the static the macro keeps) and
// once_cell's `Lazy` (SHA-512).
use ring::digest::{digest, Algorithm, SHA384, SHA512};

lazy_static::lazy_static! {
    static ref LS: &'static Algorithm = &SHA384;
}
static OC: once_cell::sync::Lazy<&'static Algorithm> = once_cell::sync::Lazy::new(|| &SHA512);

fn main() {
    let d = std::env::args().next().unwrap_or_default().into_bytes();
    println!("{} {}", digest(*LS, &d).as_ref().len(), digest(*OC, &d).as_ref().len());
}
