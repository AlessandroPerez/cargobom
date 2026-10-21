fn included(d: &[u8]) -> usize {
    ring::digest::digest(&ring::digest::SHA256, d).as_ref().len()
}
