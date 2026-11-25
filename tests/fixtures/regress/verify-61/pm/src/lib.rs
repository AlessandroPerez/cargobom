// Procedural macros that write a `macro_rules!`: it is defined, for the compiler, where the
// macro that wrote it is invoked.
use proc_macro::TokenStream;

// `#[derive(Stamp)]`: `stamp!(bytes)` hashes them.
#[proc_macro_derive(Stamp)]
pub fn stamp(_input: TokenStream) -> TokenStream {
    "macro_rules! stamp { ($d:expr) => { <sha2::Sha512 as sha2::Digest>::digest($d) }; }"
        .parse()
        .unwrap()
}

// `#[sealed]` over an item: the item, and `seal!(bytes)` that hashes them.
#[proc_macro_attribute]
pub fn sealed(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let seal: TokenStream =
        "macro_rules! seal { ($d:expr) => { <sha2::Sha384 as sha2::Digest>::digest($d) }; }"
            .parse()
            .unwrap();
    item.into_iter().chain(seal).collect()
}
