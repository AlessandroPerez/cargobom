use ring::digest;

// A closure of another crate than the program's, written over several lines: the descriptor is
// named on a later line than the closure starts on (rcgen's `sign_der(|writer| { .. })`).
pub fn tag(data: &[u8]) -> Vec<u8> {
    let run = |d: &[u8]| {
        let out = digest::digest(&digest::SHA256, d);
        out.as_ref().to_vec()
    };
    run(data)
}
