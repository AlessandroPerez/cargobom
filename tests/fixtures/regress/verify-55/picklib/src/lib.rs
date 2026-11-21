pub static CALG: &ring::digest::Algorithm = &ring::digest::SHA512_256;

// 19: a dependency the workspace renames
pub fn h19(d: &[u8]) -> Vec<u8> {
    use shax::Digest;
    shax::Sha256::digest(d).to_vec()
}
