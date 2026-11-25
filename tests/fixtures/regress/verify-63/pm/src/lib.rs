// `#[launched]` over `fn start() -> T`: the function as written, and a `main` that awaits
// `start().run()`; the awaiting statement has the span of the first token of `T`.
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

fn braced(body: TokenStream) -> TokenTree {
    TokenTree::Group(Group::new(Delimiter::Brace, body))
}

#[proc_macro_attribute]
pub fn launched(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let toks: Vec<TokenTree> = item.clone().into_iter().collect();
    let at = toks
        .iter()
        .position(|t| t.to_string() == "fn")
        .expect("a function");
    let name = toks[at + 1].to_string();
    let arrow = toks
        .windows(2)
        .position(|w| w[0].to_string() == "-" && w[1].to_string() == ">")
        .expect("a return type");
    let awaited = spanned(
        format!("let _ = {name}().run().await;").parse().unwrap(),
        toks[arrow + 2].span(),
    );
    let run: TokenStream = "let mut running = ::std::pin::pin!"
        .parse::<TokenStream>()
        .unwrap()
        .into_iter()
        .chain([TokenTree::Group(Group::new(
            Delimiter::Parenthesis,
            "async"
                .parse::<TokenStream>()
                .unwrap()
                .into_iter()
                .chain([braced(awaited)])
                .collect(),
        ))])
        .chain(
            "; let mut cx = ::std::task::Context::from_waker(::std::task::Waker::noop()); \
             while ::std::future::Future::poll(running.as_mut(), &mut cx).is_pending() {}"
                .parse::<TokenStream>()
                .unwrap(),
        )
        .collect();
    let main: TokenStream = "fn main()"
        .parse::<TokenStream>()
        .unwrap()
        .into_iter()
        .chain([braced(run)])
        .collect();
    item.into_iter().chain(main).collect()
}
