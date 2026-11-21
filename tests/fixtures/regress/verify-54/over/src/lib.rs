// An attribute that writes the function it is on again, every token at its own span, as
// `#[proc_macro_error]` does to the function that defines a macro.
use proc_macro::{Group, Span, TokenStream, TokenTree};

fn respan(ts: TokenStream, span: Span) -> TokenStream {
    ts.into_iter()
        .map(|t| match t {
            TokenTree::Group(g) => {
                let mut n = Group::new(g.delimiter(), respan(g.stream(), span));
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

#[proc_macro_attribute]
pub fn through(_attr: TokenStream, item: TokenStream) -> TokenStream {
    respan(item, Span::call_site())
}
