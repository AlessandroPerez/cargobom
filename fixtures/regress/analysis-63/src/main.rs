// round 11 regress (audit 10 probe d3): trait objects of instances of one generic type with different impls
use ring::digest::{digest, Algorithm as Digest, SHA256, SHA384, SHA512};
use std::marker::PhantomData;

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

struct W<T>(PhantomData<T>);
struct A;
struct B;
trait Gen1 { fn alg(&self) -> &'static Digest; }
impl Gen1 for W<A> { fn alg(&self) -> &'static Digest { &SHA256 } }
impl Gen1 for W<B> { fn alg(&self) -> &'static Digest { &SHA512 } }
trait Gen2 { fn alg(&self) -> &'static Digest; }
impl Gen2 for W<A> { fn alg(&self) -> &'static Digest { &SHA384 } }
impl Gen2 for W<B> { fn alg(&self) -> &'static Digest { &SHA512 } }

fn main() {
    let d = arg(0).into_bytes();
    // only W<A> is coerced to dyn Gen1; W<B>'s impl is called directly
    let g: Box<dyn Gen1> = Box::new(W::<A>(PhantomData));
    let _ = digest(g.alg(), &d);
    let _ = digest(Gen1::alg(&W::<B>(PhantomData)), &d);
    // both instances coerced to dyn Gen2
    let h: Box<dyn Gen2> = if arg(1).is_empty() { Box::new(W::<A>(PhantomData)) } else { Box::new(W::<B>(PhantomData)) };
    let _ = digest(h.alg(), &d);
}
