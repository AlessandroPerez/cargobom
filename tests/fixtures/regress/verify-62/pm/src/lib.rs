// Procedural macros that give a call they write the span of a token they were handed.
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

// `hashed!(x)`: the SHA-256 of `x`, a literal or a name; the call has the span of `x`.
#[proc_macro]
pub fn hashed(input: TokenStream) -> TokenStream {
    let arg = input.into_iter().next().expect("an argument");
    let span = arg.span();
    spanned(
        format!("<sha2::Sha256 as sha2::Digest>::digest({arg})")
            .parse()
            .unwrap(),
        span,
    )
}

// `#[keyed("name")]` over a function: the function as written, and `named()`, which hashes the
// name with SHA-384; that call has the span of the literal in the attribute.
#[proc_macro_attribute]
pub fn keyed(attr: TokenStream, item: TokenStream) -> TokenStream {
    let lit = attr.into_iter().next().expect("a literal");
    let span = lit.span();
    let call = spanned(
        format!("<sha2::Sha384 as sha2::Digest>::digest({lit}).to_vec()")
            .parse()
            .unwrap(),
        span,
    );
    let head: TokenStream = "fn named() -> Vec<u8>".parse().unwrap();
    let body = TokenTree::Group(Group::new(Delimiter::Brace, call));
    item.into_iter().chain(head).chain([body]).collect()
}

// `#[counted]` over a function: the function, its body after a call that hashes its name with
// SHA-224; that call has the span of the function's name.
#[proc_macro_attribute]
pub fn counted(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut toks: Vec<TokenTree> = item.into_iter().collect();
    let at = toks
        .iter()
        .position(|t| t.to_string() == "fn")
        .expect("a function");
    let name = toks[at + 1].clone();
    let Some(TokenTree::Group(body)) = toks.pop() else {
        panic!("a body")
    };
    let call = spanned(
        format!("let _ = <sha2::Sha224 as sha2::Digest>::digest(\"{name}\");")
            .parse()
            .unwrap(),
        name.span(),
    );
    let new: TokenStream = call.into_iter().chain(body.stream()).collect();
    toks.push(TokenTree::Group(Group::new(body.delimiter(), new)));
    toks.into_iter().collect()
}
