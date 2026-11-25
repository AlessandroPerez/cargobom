// Procedural function-like macros: one that gives the call it writes the span of the token it
// was handed, one that hands its input back.
use proc_macro::{Group, Span, TokenStream, TokenTree};

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

// `hashed!(x)`: the SHA-256 of `x`; the call has the span of `x`.
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

// Its input, handed back: every token is where it was written.
#[proc_macro]
pub fn as_is(input: TokenStream) -> TokenStream {
    input
}
