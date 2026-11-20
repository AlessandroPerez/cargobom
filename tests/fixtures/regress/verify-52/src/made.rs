//! tendermint (`tendermint_pb_modules! { .. }`): a macro defined in another file writes a module
//! around the items it is handed, once for each version; the items are in `made::v1` and
//! `made::v2`, their code where this file has it.
//! near-crypto (`prs!(x)`, `hash_s!(..)`): macros defined in another file write calls of that
//! file's generic functions; two in one function, for two digests, which the text of the
//! invocations does not tell apart.

versions! {
    use sha2::Digest;

    pub fn id(data: &[u8]) -> Vec<u8> {
        Hasher::digest(data).to_vec()
    }
}

pub fn proof(input: &[u8]) -> Vec<u8> {
    let k = long!(input);
    let c = short!(input, &k);
    [k, c].concat()
}
