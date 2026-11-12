// mongodb's `#[action_impl]`: on `impl Action for X { fn execute(self) -> T { BODY } }`, keeps
// the trait's method as a call of `X::run` and writes `impl X { fn run(self) -> T { BODY } }`,
// the body's tokens (and spans) moved.
use proc_macro::{Delimiter, Group, TokenStream, TokenTree};

#[proc_macro_attribute]
pub fn action(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let toks: Vec<TokenTree> = input.into_iter().collect();
    let for_at = toks
        .iter()
        .position(|t| t.to_string() == "for")
        .expect("an impl of a trait");
    let ty = toks[for_at + 1].to_string();
    let Some(TokenTree::Group(items)) = toks.last() else {
        panic!("an impl block")
    };
    let inner: Vec<TokenTree> = items.stream().into_iter().collect();
    // the method's signature up to its body, and its body
    let body_at = inner
        .iter()
        .rposition(|t| matches!(t, TokenTree::Group(g) if g.delimiter() == Delimiter::Brace))
        .expect("a method body");
    let TokenTree::Group(body) = &inner[body_at] else {
        unreachable!()
    };
    let sig: TokenStream = inner[..body_at].iter().cloned().collect();
    let ret: TokenStream = {
        let s: Vec<TokenTree> = sig.clone().into_iter().collect();
        let arrow = s
            .iter()
            .position(|t| matches!(t, TokenTree::Punct(p) if p.as_char() == '-'))
            .expect("a return type");
        s[arrow..].iter().cloned().collect()
    };
    let mut out: TokenStream = toks[..toks.len() - 1].iter().cloned().collect();
    let mut kept = sig.clone();
    kept.extend(
        "{ self.run() }"
            .parse::<TokenStream>()
            .unwrap(),
    );
    out.extend([TokenTree::Group(Group::new(Delimiter::Brace, kept))]);
    let mut run: TokenStream = format!("impl {ty} {{ pub fn run(self) {ret} }}")
        .parse::<TokenStream>()
        .unwrap();
    // the body in place of the empty one the text above leaves out
    let mut parts: Vec<TokenTree> = run.into_iter().collect();
    let Some(TokenTree::Group(g)) = parts.pop() else {
        unreachable!()
    };
    let mut method: Vec<TokenTree> = g.stream().into_iter().collect();
    method.push(TokenTree::Group(body.clone()));
    parts.push(TokenTree::Group(Group::new(
        Delimiter::Brace,
        method.into_iter().collect(),
    )));
    run = parts.into_iter().collect();
    out.extend(run);
    out
}
