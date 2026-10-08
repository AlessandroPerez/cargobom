use proc_macro::TokenStream;

#[proc_macro_derive(Hashy)]
pub fn hashy(input: TokenStream) -> TokenStream {
    let s = input.to_string();
    let name = s.split_whitespace().skip_while(|w| *w != "struct").nth(1).unwrap().trim_end_matches(';').to_string();
    format!("impl {name} {{ pub fn hashy() -> usize {{ ring::digest::digest(&ring::digest::SHA256, b\"d\").as_ref().len() }} }}").parse().unwrap()
}

#[proc_macro_attribute]
pub fn hashed(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut out = item;
    let extra: TokenStream = "pub fn generated_384() -> usize { ring::digest::digest(&ring::digest::SHA384, b\"a\").as_ref().len() }".parse().unwrap();
    out.extend(extra);
    out
}
