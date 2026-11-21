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

// A free function a macro writes and its invocation names, in a crate the program depends on
// (hpke-rs-rust-crypto's `implement_aead!(aes128_seal, aes128_open, ..)` under
// openmls_rust_crypto). Its name reads as the source's own; of another crate's function the
// compiler keeps no record of the expansion that defines it, and what says a macro wrote it is
// the expansion its header is written in.
macro_rules! digest_fn {
    ($name:ident, $alg:ident) => {
        pub fn $name(data: &[u8]) -> Vec<u8> {
            digest::digest(&digest::$alg, data).as_ref().to_vec()
        }
    };
}

digest_fn!(wide, SHA384);
