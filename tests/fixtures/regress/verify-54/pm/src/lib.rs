// Procedural macros that give their code the spans real ones do.
use proc_macro::{Delimiter, Group, Ident, Spacing, Span, TokenStream, TokenTree};

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

// `#[boxed] async fn f(..) -> T { body }` becomes `fn f(..) -> Pin<Box<dyn Future<Output = T> +
// '_>> { Box::pin(async move { body }) }`, as `#[async_trait]` rewrites a trait's `async fn`.
// The `async move { .. }` block has the span of the `async` it was made from: the compiler's
// span of the block is that keyword's, and holds none of the body.
#[proc_macro_attribute]
pub fn boxed(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let toks: Vec<TokenTree> = item.into_iter().collect();
    let at = toks
        .iter()
        .position(|t| t.to_string() == "async")
        .expect("an async fn");
    let asynch = toks[at].span();
    let arrow = toks
        .iter()
        .rposition(|t| t.to_string() == ">" )
        .filter(|&k| k > 0 && toks[k - 1].to_string() == "-")
        .or_else(|| {
            (1..toks.len()).find(|&k| toks[k - 1].to_string() == "-" && toks[k].to_string() == ">")
        })
        .expect("a return type");
    let body = toks.last().expect("a body").clone();
    let ret: TokenStream = toks[arrow + 1..toks.len() - 1].iter().cloned().collect();
    let mut out: Vec<TokenTree> = toks[..at].to_vec();
    out.extend(toks[at + 1..arrow - 1].iter().cloned());
    let head: TokenStream = format!(
        "-> ::std::pin::Pin<::std::boxed::Box<dyn ::std::future::Future<Output = {ret}> + '_>>"
    )
    .parse()
    .unwrap();
    out.extend(head);
    let mut block = Group::new(Delimiter::Brace, TokenStream::from(body));
    block.set_span(asynch);
    let inner: Vec<TokenTree> = vec![
        TokenTree::Ident(Ident::new("async", asynch)),
        TokenTree::Ident(Ident::new("move", asynch)),
        TokenTree::Group(block),
    ];
    let pin: TokenStream = "::std::boxed::Box::pin".parse().unwrap();
    let mut whole: Vec<TokenTree> = pin.into_iter().collect();
    whole.push(TokenTree::Group(Group::new(
        Delimiter::Parenthesis,
        inner.into_iter().collect(),
    )));
    out.push(TokenTree::Group(Group::new(
        Delimiter::Brace,
        whole.into_iter().collect(),
    )));
    out.into_iter().collect()
}

// `#[traced] fn f(..) -> T { body }` becomes `fn f(..) -> T { (move || { body })() }`, as
// `#[instrument(ret)]` wraps a function's body in a closure it calls: the closure's own tokens
// have the attribute's span.
#[proc_macro_attribute]
pub fn traced(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut toks: Vec<TokenTree> = item.into_iter().collect();
    let body = toks.pop().expect("a body");
    let call: TokenStream = "(move || BODY)()".parse().unwrap();
    let call: TokenStream = call
        .into_iter()
        .map(|t| match t {
            TokenTree::Group(g) if g.delimiter() == Delimiter::Parenthesis && !g.stream().is_empty() => {
                let inner: TokenStream = g
                    .stream()
                    .into_iter()
                    .map(|t| if t.to_string() == "BODY" { body.clone() } else { t })
                    .collect();
                TokenTree::Group(Group::new(Delimiter::Parenthesis, inner))
            }
            t => t,
        })
        .collect();
    toks.push(TokenTree::Group(Group::new(Delimiter::Brace, call)));
    toks.into_iter().collect()
}

// A derive that writes `impl crate::summed::Summed for X`, hashing the type's first field. The
// call has the span of that field's type, as serde's derives give a field's code its field's
// span: under a `macro_rules!` that writes the type, the call reads as that macro's own code.
#[proc_macro_derive(Summed)]
pub fn summed(input: TokenStream) -> TokenStream {
    let toks: Vec<TokenTree> = input.into_iter().collect();
    let at = toks
        .iter()
        .position(|t| t.to_string() == "struct")
        .expect("a struct");
    let name = toks[at + 1].to_string();
    let field = match &toks[at + 2] {
        TokenTree::Group(g) => g
            .stream()
            .into_iter()
            .last()
            .map(|t| t.span())
            .expect("a field"),
        _ => panic!("a tuple struct"),
    };
    let call: TokenStream = "<sha2::Sha512_224 as sha2::Digest>::digest".parse().unwrap();
    let call = respan(call, field);
    let head: TokenStream =
        format!("impl crate::summed::Summed for {name} {{ fn sum(&self) -> Vec<u8> {{ CALL(&self.0).to_vec() }} }}")
            .parse()
            .unwrap();
    fn put(ts: TokenStream, call: &TokenStream) -> TokenStream {
        ts.into_iter()
            .flat_map(|t| match t {
                TokenTree::Group(g) => {
                    let n = Group::new(g.delimiter(), put(g.stream(), call));
                    vec![TokenTree::Group(n)]
                }
                t if t.to_string() == "CALL" => call.clone().into_iter().collect(),
                t => vec![t],
            })
            .collect()
    }
    put(head, &call)
}

// `#[guarded] async fn f(a: A) -> T { body }` becomes `async fn f(a: A) -> T { async fn inner(a:
// A) -> T { body } inner(a).await }`, as actix-web-grants' `#[protect(..)]` awaits the function
// it guards: the `.await` is the attribute's own code, and has the attribute's span.
#[proc_macro_attribute]
pub fn guarded(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let toks: Vec<TokenTree> = item.into_iter().collect();
    let at = toks
        .iter()
        .position(|t| t.to_string() == "fn")
        .expect("a fn");
    let TokenTree::Group(args) = &toks[at + 2] else {
        panic!("arguments");
    };
    let args: Vec<TokenTree> = args.stream().into_iter().collect();
    let names: Vec<String> = args
        .windows(2)
        .filter(|w| {
            matches!(&w[0], TokenTree::Ident(_))
                && matches!(&w[1], TokenTree::Punct(p) if p.as_char() == ':' && p.spacing() == Spacing::Alone)
        })
        .map(|w| w[0].to_string())
        .collect();
    let mut body = toks.clone();
    body[at + 1] = TokenTree::Ident(Ident::new("inner", toks[at + 1].span()));
    body.extend(
        format!("inner({}).await", names.join(", "))
            .parse::<TokenStream>()
            .unwrap(),
    );
    let mut out = toks[..toks.len() - 1].to_vec();
    out.push(TokenTree::Group(Group::new(
        Delimiter::Brace,
        body.into_iter().collect(),
    )));
    out.into_iter().collect()
}

// A derive whose own function an attribute macro writes again (conflate's `Merge` under
// `#[proc_macro_error]`): the compiler has the derive defined where that attribute is, on a
// line that reads no `fn`. What says the macro is procedural is its package's manifest.
#[proc_macro_derive(Tagged)]
#[over::through]
pub fn tagged(input: TokenStream) -> TokenStream {
    let toks: Vec<TokenTree> = input.into_iter().collect();
    let at = toks
        .iter()
        .position(|t| t.to_string() == "struct")
        .expect("a struct");
    let name = toks[at + 1].to_string();
    format!(
        "impl crate::tagged::Tagged for {name} {{ fn tag(&self) -> Vec<u8> {{ \
         <sha2::Sha512_256 as sha2::Digest>::digest(&self.0).to_vec() }} }}"
    )
    .parse()
    .unwrap()
}
