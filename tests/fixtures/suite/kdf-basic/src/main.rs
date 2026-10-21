use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

fn main() {
    let mut master = [0u8; 32];
    pbkdf2_hmac::<Sha256>(b"correct horse", b"pepper-salt", 600_000, &mut master);
    let hk = Hkdf::<Sha256>::new(Some(&b"context-salt"[..]), &master);
    let mut okm = [0u8; 42];
    hk.expand(b"session", &mut okm).unwrap();
    println!("{:02x?}", &okm[..4]);
}
