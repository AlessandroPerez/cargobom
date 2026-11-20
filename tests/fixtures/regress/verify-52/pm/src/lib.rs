// A derive whose code hashes the type's first field: `impl X { pub fn fingerprint(&self) ->
// Vec<u8> }`. The code has the span of the derive's name in the attribute, as a derive's does.
use proc_macro::{TokenStream, TokenTree};

#[proc_macro_derive(Fingerprint)]
pub fn fingerprint(input: TokenStream) -> TokenStream {
    let toks: Vec<TokenTree> = input.into_iter().collect();
    let at = toks
        .iter()
        .position(|t| t.to_string() == "struct")
        .expect("a struct");
    let name = toks[at + 1].to_string();
    format!(
        "impl {name} {{ pub fn fingerprint(&self) -> Vec<u8> {{ \
         <sha2::Sha224 as sha2::Digest>::digest(&self.0).to_vec() }} }}"
    )
    .parse()
    .unwrap()
}

// A derive that writes a trait impl for the type, `impl crate::wrapped::Tagged for X`.
#[proc_macro_derive(Tagged)]
pub fn tagged(input: TokenStream) -> TokenStream {
    let toks: Vec<TokenTree> = input.into_iter().collect();
    let at = toks
        .iter()
        .position(|t| t.to_string() == "struct")
        .expect("a struct");
    let name = toks[at + 1].to_string();
    format!(
        "impl crate::wrapped::Tagged for {name} {{ fn tag_bytes(&self) -> Vec<u8> {{ \
         <sha2::Sha224 as sha2::Digest>::digest(&self.0).to_vec() }} }}"
    )
    .parse()
    .unwrap()
}

// A derive that writes `impl crate::coded::Coded for X`, whose `digest` runs one of the
// hashers of `crate::coded` (as multihash-derive's `MultihashDigest` runs each variant's).
#[proc_macro_derive(Coded)]
pub fn coded(input: TokenStream) -> TokenStream {
    let toks: Vec<TokenTree> = input.into_iter().collect();
    let at = toks
        .iter()
        .position(|t| t.to_string() == "struct")
        .expect("a struct");
    let name = toks[at + 1].to_string();
    format!(
        "impl crate::coded::Coded for {name} {{ fn digest(&self, data: &[u8]) -> Vec<u8> {{ \
         use crate::coded::Hasher as _; \
         match self.0 {{ \
         0 => {{ let mut h = crate::coded::two::Sha2_256::default(); h.update(data); h.finalize() }} \
         1 => {{ let mut h = crate::coded::two::Sha2_512::default(); h.update(data); h.finalize() }} \
         2 => {{ let mut h = crate::coded::Truncated::<16>::default(); h.update(data); h.finalize() }} \
         _ => {{ let mut h = crate::coded::three::Sha2_384::default(); h.update(data); h.finalize() }} \
         }} }} }}"
    )
    .parse()
    .unwrap()
}
