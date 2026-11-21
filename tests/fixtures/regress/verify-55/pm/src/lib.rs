// Procedural macros: what each writes has the span of its invocation, but for the tokens it
// takes from its input.
use proc_macro::{Delimiter, Group, TokenStream, TokenTree};

// `#[wrapped] fn f(..) -> T { body }` becomes `fn f(..) -> T { (move || { body })() }`: the
// function keeps its tokens, the closure is the attribute's.
#[proc_macro_attribute]
pub fn wrapped(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut toks: Vec<TokenTree> = item.into_iter().collect();
    let body = toks.pop().expect("a body");
    let mut call: Vec<TokenTree> = "move ||"
        .parse::<TokenStream>()
        .unwrap()
        .into_iter()
        .collect();
    call.push(body);
    let closure = TokenTree::Group(Group::new(
        Delimiter::Parenthesis,
        call.into_iter().collect(),
    ));
    let args = TokenTree::Group(Group::new(Delimiter::Parenthesis, TokenStream::new()));
    toks.push(TokenTree::Group(Group::new(
        Delimiter::Brace,
        [closure, args].into_iter().collect(),
    )));
    toks.into_iter().collect()
}

// A derive: the impl, its method and the call are all the derive's.
#[proc_macro_derive(Sum)]
pub fn sum(input: TokenStream) -> TokenStream {
    let toks: Vec<TokenTree> = input.into_iter().collect();
    let at = toks
        .iter()
        .position(|t| t.to_string() == "struct")
        .expect("a struct");
    let name = toks[at + 1].to_string();
    format!(
        "impl Sum for {name} {{ fn sum(&self) -> Vec<u8> {{ \
         <sha2::Sha512_256 as sha2::Digest>::digest(&self.0).to_vec() }} }}"
    )
    .parse()
    .unwrap()
}

// A free function the invocation names: the name keeps the span the source gave it, the rest is
// the macro's.
#[proc_macro]
pub fn make_fn(input: TokenStream) -> TokenStream {
    let name = input.into_iter().next().expect("a name");
    let code: TokenStream = "pub fn NAME(d: &[u8]) -> Vec<u8> { \
                             <sha2::Sha224 as sha2::Digest>::digest(d).to_vec() }"
        .parse()
        .unwrap();
    code.into_iter()
        .map(|t| {
            if t.to_string() == "NAME" {
                name.clone()
            } else {
                t
            }
        })
        .collect()
}

// Its input, handed back: a macro defines the item, and every token is where the source wrote
// it.
#[proc_macro]
pub fn as_is(input: TokenStream) -> TokenStream {
    input
}

// An attribute that writes another over the item it is on (maybe-async's `#[maybe_async]`
// writes `#[async_trait]`): the attribute it writes has its own span, and does not read there.
#[proc_macro_attribute]
pub fn twice(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut out: TokenStream = "#[pm::wrapped]".parse().unwrap();
    out.extend(item);
    out
}

// A procedural macro that writes the invocation of a `macro_rules!` one: that invocation has
// this one's span.
#[proc_macro]
pub fn via_rules(input: TokenStream) -> TokenStream {
    let name = input.into_iter().next().expect("a name");
    let code: TokenStream = "mac::free_fn!(NAME, Sha384);".parse().unwrap();
    fn put(ts: TokenStream, name: &TokenTree) -> TokenStream {
        ts.into_iter()
            .map(|t| match t {
                TokenTree::Group(g) => {
                    TokenTree::Group(Group::new(g.delimiter(), put(g.stream(), name)))
                }
                t if t.to_string() == "NAME" => name.clone(),
                t => t,
            })
            .collect()
    }
    put(code, &name)
}

// A derive that writes the invocation of a `macro_rules!` one inside the impl it makes.
#[proc_macro_derive(Ruled)]
pub fn ruled(input: TokenStream) -> TokenStream {
    let toks: Vec<TokenTree> = input.into_iter().collect();
    let at = toks
        .iter()
        .position(|t| t.to_string() == "struct")
        .expect("a struct");
    let name = toks[at + 1].to_string();
    format!("impl {name} {{ mac::method_in!(ruled, sha2::Sha512); }}")
        .parse()
        .unwrap()
}
