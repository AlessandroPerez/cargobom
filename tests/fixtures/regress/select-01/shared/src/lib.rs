use sha2::{Digest, Sha512};

pub fn fingerprint(data: &[u8]) -> Vec<u8> {
    Sha512::digest(data).to_vec()
}

/// Public, but no artifact of `-p app` calls it: compiled, not reached (`shared` is a
/// dependency here, its API no artifact).
pub fn unused(data: &[u8]) -> Vec<u8> {
    use sha3::Sha3_256;
    Sha3_256::digest(data).to_vec()
}
