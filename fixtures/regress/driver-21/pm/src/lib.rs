// A procedural derive that spans its generated code at an input token (`quote_spanned!`), the
// field name here: the code is the derive's, cited at `#[derive(..)]` (fourth audit round).
use proc_macro::{Span, TokenStream, TokenTree};

fn respan(ts: TokenStream, sp: Span) -> TokenStream {
    ts.into_iter()
        .map(|t| match t {
            TokenTree::Group(g) => {
                let mut n = proc_macro::Group::new(g.delimiter(), respan(g.stream(), sp));
                n.set_span(sp);
                TokenTree::Group(n)
            }
            mut other => {
                other.set_span(sp);
                other
            }
        })
        .collect()
}

// generates `impl S { pub fn digest_key(&self) -> usize { .. } }` with every token spanned at the
// first field's name, as `quote_spanned!(field.span() => ..)` does
#[proc_macro_derive(HashField)]
pub fn hash_field(input: TokenStream) -> TokenStream {
    let toks: Vec<TokenTree> = input.into_iter().collect();
    let name = toks
        .iter()
        .skip_while(|t| t.to_string() != "struct")
        .nth(1)
        .unwrap()
        .to_string();
    let body = match toks.last().unwrap() {
        TokenTree::Group(g) => g.stream(),
        _ => panic!(),
    };
    let field = body.into_iter().find_map(|t| match t {
        TokenTree::Ident(i) if i.to_string() != "pub" => Some(i),
        _ => None,
    }).unwrap();
    let generated: TokenStream = format!(
        "::sha2::Digest::finalize(<::sha2::Sha512 as ::sha2::Digest>::new_with_prefix(&self.{field})).len()"
    )
    .parse()
    .unwrap();
    let generated = respan(generated, field.span());
    let out: TokenStream = format!("impl {name} {{ pub fn digest_key(&self) -> usize {{ GEN }} }}")
        .replace("GEN", &generated.to_string())
        .parse()
        .unwrap();
    // put the respanned body in place of the text version
    let mut res = Vec::new();
    for t in out {
        match t {
            TokenTree::Group(g) if g.delimiter() == proc_macro::Delimiter::Brace => {
                let inner: Vec<TokenTree> = g.stream().into_iter().map(|t| match t {
                    TokenTree::Group(b) if b.delimiter() == proc_macro::Delimiter::Brace => {
                        TokenTree::Group(proc_macro::Group::new(proc_macro::Delimiter::Brace, generated.clone()))
                    }
                    o => o,
                }).collect();
                res.push(TokenTree::Group(proc_macro::Group::new(proc_macro::Delimiter::Brace, inner.into_iter().collect())));
            }
            o => res.push(o),
        }
    }
    res.into_iter().collect()
}
