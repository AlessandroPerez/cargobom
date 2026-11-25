// What a derive writes for a field often has the field's span
// (`quote_spanned!(field.span()=> ..)`), and a field starts at its documentation comment.
use proc_macro::{Delimiter, Group, Span, TokenStream, TokenTree};

fn spanned(code: TokenStream, span: Span) -> TokenStream {
    code.into_iter()
        .map(|t| match t {
            TokenTree::Group(g) => {
                let mut n = Group::new(g.delimiter(), spanned(g.stream(), span));
                n.set_span(span);
                TokenTree::Group(n)
            }
            mut t => {
                t.set_span(span);
                t
            }
        })
        .collect()
}

// `#[derive(Tagged)]` on a struct of named fields: `tag` hashes the first field. The impl and
// the method are the derive's; the call has the span of the field's first token.
#[proc_macro_derive(Tagged)]
pub fn tagged(input: TokenStream) -> TokenStream {
    let toks: Vec<TokenTree> = input.into_iter().collect();
    let k = toks
        .iter()
        .position(|t| t.to_string() == "struct")
        .expect("a struct");
    let name = toks[k + 1].to_string();
    let TokenTree::Group(fields) = &toks[k + 2] else {
        panic!("named fields")
    };
    let fields: Vec<TokenTree> = fields.stream().into_iter().collect();
    let colon = fields
        .iter()
        .position(|t| t.to_string() == ":")
        .expect("a field");
    let field = fields[colon - 1].to_string();
    let call = spanned(
        format!("<sha2::Sha512 as sha2::Digest>::digest(&self.{field})")
            .parse()
            .unwrap(),
        fields[0].span(),
    );
    let body: TokenStream = call
        .into_iter()
        .chain(".to_vec()".parse::<TokenStream>().unwrap())
        .collect();
    let method: TokenStream = "fn tag(&self) -> Vec<u8>"
        .parse::<TokenStream>()
        .unwrap()
        .into_iter()
        .chain([TokenTree::Group(Group::new(Delimiter::Brace, body))])
        .collect();
    format!("impl {name}")
        .parse::<TokenStream>()
        .unwrap()
        .into_iter()
        .chain([TokenTree::Group(Group::new(Delimiter::Brace, method))])
        .collect()
}
