use sha2::{Digest, Sha224};

pub fn socket_id(path: &[u8]) -> Vec<u8> {
    // in `verify_48::platform::socket_id`: the file is the module `platform`
    Sha224::digest(path).to_vec()
}
