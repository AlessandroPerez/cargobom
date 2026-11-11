// jj's `#[derive(ContentHash)]`: an `impl ContentHash` whose `hash` calls each field's `hash`,
// the call spanned at the field's type (`quote_spanned!(ty.span() => ..)`).
use proc_macro::{Delimiter, Group, Span, TokenStream, TokenTree};

fn respan(ts: TokenStream, sp: Span) -> TokenStream {
    ts.into_iter()
        .map(|t| match t {
            TokenTree::Group(g) => {
                let mut n = Group::new(g.delimiter(), respan(g.stream(), sp));
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

#[proc_macro_derive(ContentHash)]
pub fn content_hash(input: TokenStream) -> TokenStream {
    let toks: Vec<TokenTree> = input.into_iter().collect();
    let at = toks
        .iter()
        .position(|t| t.to_string() == "struct")
        .expect("a struct");
    let name = toks[at + 1].to_string();
    let body = toks[at + 2..]
        .iter()
        .find_map(|t| match t {
            TokenTree::Group(g)
                if matches!(g.delimiter(), Delimiter::Brace | Delimiter::Parenthesis) =>
            {
                Some(g.clone())
            }
            _ => None,
        })
        .expect("fields");
    let named = body.delimiter() == Delimiter::Brace;
    // the fields: split at the commas outside angle brackets
    let mut fields: Vec<Vec<TokenTree>> = vec![Vec::new()];
    let mut depth = 0;
    for t in body.stream() {
        if let TokenTree::Punct(p) = &t {
            match p.as_char() {
                '<' => depth += 1,
                '>' => depth -= 1,
                ',' if depth == 0 => {
                    fields.push(Vec::new());
                    continue;
                }
                _ => {}
            }
        }
        fields.last_mut().unwrap().push(t);
    }
    let mut calls = TokenStream::new();
    for (i, f) in fields.iter().filter(|f| !f.is_empty()).enumerate() {
        // a named field's type follows its `:`; a tuple field's follows its attributes and
        // visibility
        let (access, ty) = if named {
            let colon = f
                .iter()
                .position(|t| matches!(t, TokenTree::Punct(p) if p.as_char() == ':'))
                .expect("a named field");
            (f[colon - 1].to_string(), &f[colon + 1])
        } else {
            let ty = f
                .iter()
                .rev()
                .take_while(|t| {
                    !matches!(t, TokenTree::Ident(i) if i.to_string() == "pub")
                        && !matches!(t, TokenTree::Group(g) if g.delimiter() == Delimiter::Bracket)
                })
                .last()
                .expect("a tuple field");
            (i.to_string(), ty)
        };
        let call: TokenStream =
            format!("crate::content_hash::ContentHash::hash(&self.{access}, state);")
                .parse()
                .unwrap();
        calls.extend(respan(call, ty.span()));
    }
    let mut out: Vec<TokenTree> = format!(
        "impl crate::content_hash::ContentHash for {name} {{ \
         fn hash(&self, state: &mut impl ::sha2::digest::Update) {{ }} }}"
    )
    .parse::<TokenStream>()
    .unwrap()
    .into_iter()
    .collect();
    // the calls, in the method's body
    let Some(TokenTree::Group(items)) = out.pop() else {
        unreachable!()
    };
    let mut method: Vec<TokenTree> = items.stream().into_iter().collect();
    method.pop();
    method.push(TokenTree::Group(Group::new(Delimiter::Brace, calls)));
    out.push(TokenTree::Group(Group::new(
        Delimiter::Brace,
        method.into_iter().collect(),
    )));
    out.into_iter().collect()
}

// derive_more's `Debug`: code for a field, spanned where the macro is called
#[proc_macro_derive(Show)]
pub fn show(input: TokenStream) -> TokenStream {
    let toks: Vec<TokenTree> = input.into_iter().collect();
    let at = toks
        .iter()
        .position(|t| t.to_string() == "struct")
        .expect("a struct");
    let name = toks[at + 1].to_string();
    let Some(TokenTree::Group(body)) = toks.last() else {
        panic!("fields")
    };
    let fields: Vec<TokenTree> = body.stream().into_iter().collect();
    let colon = fields
        .iter()
        .position(|t| matches!(t, TokenTree::Punct(p) if p.as_char() == ':'))
        .expect("a named field");
    let field = fields[colon - 1].to_string();
    format!(
        "impl {name} {{ pub fn show(&self) -> String {{ self.{field}.digest().to_string() }} }}"
    )
    .parse()
    .unwrap()
}
