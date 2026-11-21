pub fn included17(d: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha512_224::digest(d).to_vec()
}
