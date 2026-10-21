pub fn derive(ikm: &[u8]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, ikm);
    let mut out = [0u8; 32];
    hk.expand(b"i", &mut out).unwrap();
    out
}
pub fn unused(d: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha512_256::digest(d).into()
}
