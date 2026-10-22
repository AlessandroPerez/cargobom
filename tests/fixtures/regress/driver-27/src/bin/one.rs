// `main`'s error is printed with its `Debug` by the standard library (`Termination::report`):
// that impl runs. SHA-1: bin one.
use ring::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY, SHA256};
struct Failed(Vec<u8>);
impl std::fmt::Debug for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", digest(&SHA1_FOR_LEGACY_USE_ONLY, &self.0).as_ref())
    }
}
fn main() -> Result<(), Failed> {
    let d = std::env::args().next().unwrap_or_default().into_bytes();
    let _ = d27::shared(&SHA256, &d);
    if d.is_empty() { return Err(Failed(d)); }
    Ok(())
}
