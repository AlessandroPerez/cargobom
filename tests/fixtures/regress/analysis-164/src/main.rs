// a universal hash used on its own, not inside the AEAD it is part of: Poly1305 by its registry
// name; GHASH and POLYVAL, which the registry does not name, unknown, never dropped
use poly1305::universal_hash::{KeyInit, UniversalHash};
fn main() {
    let d = std::env::args().next().unwrap_or_default().into_bytes();
    let k = [7u8; 32];
    let _ = poly1305::Poly1305::new(&k.into()).compute_unpadded(&d); // Poly1305
    let mut p = poly1305::Poly1305::new(&k.into());
    p.update_padded(&d); // Poly1305
    let _ = p.finalize(); // Poly1305
    let h = [9u8; 16];
    let mut g = ghash::GHash::new(&h.into());
    g.update_padded(&d); // an unknown MAC (GHASH)
    let _ = g.finalize(); // an unknown MAC (GHASH)
    let mut v = polyval::Polyval::new(&h.into());
    v.update_padded(&d); // an unknown MAC (POLYVAL)
    let _ = v.verify(&[0u8; 16].into()); // an unknown MAC (POLYVAL)
}
