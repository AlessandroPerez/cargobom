use proc_macro::TokenStream;

/// expands to a SHA-256 digest of its argument
#[proc_macro]
pub fn hash_it(input: TokenStream) -> TokenStream {
    format!("::sha2::Sha256::digest({input})").parse().unwrap()
}
