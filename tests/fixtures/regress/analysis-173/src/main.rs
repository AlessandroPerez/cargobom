// A key buffer filled only in part keeps its literal bytes: provenance is a may-analysis, so a
// zeroed key half of which a call fills (`fill_bytes(&mut k1[..16])`, a `split_at_mut` half) is
// `partly hard-coded`, beside what fills it, and gives no hard-coded-key finding (the key is
// not a literal). A whole fill replaces the zeros (k3), and a literal on one way stays one.
use aes_gcm::aead::KeyInit;
use aes_gcm::Aes256Gcm;
use rand::rngs::OsRng;
use rand::RngCore;

fn main() {
    let some = std::env::args().count() > 1;
    let mut k1 = [0u8; 32];
    OsRng.fill_bytes(&mut k1[..16]);
    let mut k2 = [0u8; 32];
    {
        let (a, _b) = k2.split_at_mut(16);
        OsRng.fill_bytes(a);
    }
    let mut k3 = [0u8; 32];
    OsRng.fill_bytes(&mut k3);
    let mut k4 = [0u8; 32];
    OsRng.fill_bytes(&mut k4);
    if some {
        k4 = [3u8; 32];
    }
    let n = Aes256Gcm::new_from_slice(&k1).is_ok() as u8
        + Aes256Gcm::new_from_slice(&k2).is_ok() as u8
        + Aes256Gcm::new_from_slice(&k3).is_ok() as u8
        + Aes256Gcm::new_from_slice(&k4).is_ok() as u8;
    println!("{n}");
}
