// Closures handed to a standard-library combinator that runs them on the receiver's value or
// elements, the algorithm used inside the closure: the cases where following the receiver into
// the closure's parameter must not claim too much. Each call says what can reach it.
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
type D = &'static Digest;
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn n(i: usize) -> usize { arg(i).len() }
fn other<F: Fn(&D) -> usize>(f: F) -> usize { f(&(&SHA1 as D)) }
struct Cfg { alg: D, other: D }
fn h1(a: &D) -> usize { digest(a, b"h1").as_ref().len() } // SHA-512, SHA-256, SHA-384
fn h2(a: D) -> usize { digest(a, b"h2").as_ref().len() } // SHA-512, SHA-384
fn h3(a: D) -> usize { digest(a, b"h3").as_ref().len() } // SHA-1, SHA-256
fn mk() -> impl Fn(D) -> usize { |a| digest(a, b"mk").as_ref().len() } // SHA-384
fn algs(xs: &'static [D]) -> impl Iterator<Item = usize> { xs.iter().map(|a| digest(a, b"it").as_ref().len()) } // SHA-512
static XS: [D; 1] = [&SHA512];

fn main() {
    let d = arg(0).into_bytes();
    // each element of an array
    let a1: [D; 2] = [&SHA256, &SHA384];
    let _: usize = a1.iter().map(|a| digest(a, &d).as_ref().len()).sum(); // SHA-256, SHA-384
    // `for_each` over a slice the caller passes
    let a2: &[D] = &[&SHA512];
    a2.iter().for_each(|a| { let _ = digest(a, &d); }); // SHA-512
    // a closure value copied and also handed to the program's function running it on another value
    let f = |a: &D| digest(a, &d).as_ref().len(); // SHA-256, SHA-384, SHA-1
    let _: usize = a1.iter().map(f).sum();
    let _ = other(f);
    // called directly and through a trait object made of it
    let g = |a: D| digest(a, &d).as_ref().len(); // SHA-256, SHA-1
    let _ = g(&SHA256);
    let gd: &dyn Fn(D) -> usize = &g;
    let _ = gd(&SHA1);
    // called directly and a copy handed to `Option::map`
    let k = |a: D| digest(a, &d).as_ref().len(); // SHA-512, SHA-384
    let _ = k(&SHA512);
    let _ = Some(&SHA384 as D).map(k);
    // the program's functions called directly and named in a combinator
    let _ = h1(&(&SHA512 as D));
    let _: usize = a1.iter().map(h1).sum();
    let _ = h2(&SHA512);
    let _ = Some(&SHA384 as D).map(h2);
    // ... and boxed as a trait object
    let _ = h3(&SHA256);
    let hb: Box<dyn Fn(D) -> usize> = Box::new(h3);
    let _ = hb(&SHA1);
    // a closure boxed as a trait object and called
    let cb: Box<dyn Fn(D) -> usize> = Box::new(|a| digest(a, b"cb").as_ref().len()); // SHA-512
    let _ = cb(&SHA512);
    // returned as itself, and inside the adaptor a combinator makes
    let _ = mk()(&SHA384);
    let _: usize = algs(&XS).sum();
    // run by `sort_by` on the elements
    let mut sv: Vec<D> = vec![&SHA256, &SHA1];
    sv.sort_by(|x, y| digest(x, b"x").as_ref().len().cmp(&digest(y, b"y").as_ref().len())); // SHA-256, SHA-1
    // through `enumerate`: the element is the tuple's second part
    let _: usize = a1.iter().enumerate().map(|(i, a)| i + digest(a, &d).as_ref().len()).sum(); // SHA-256, SHA-384
    // through `zip`: one part from each
    let a3: [D; 1] = [&SHA1];
    let _: usize = a1.iter().zip(a3.iter()).map(|(a, b)| digest(a, &d).as_ref().len() + digest(b, &d).as_ref().len()).sum(); // SHA-256, SHA-384 / SHA-1
    // after `filter`: some of the elements
    let _: usize = a1.iter().filter(|a| a.output_len() > n(1)).map(|a| digest(a, &d).as_ref().len()).sum(); // SHA-256, SHA-384
    // a field of each struct element
    let cs = [Cfg { alg: &SHA384, other: &SHA1 }, Cfg { alg: &SHA512, other: &SHA1 }];
    let _: usize = cs.iter().map(|c| digest(c.alg, &d).as_ref().len()).sum(); // SHA-384, SHA-512
    let _: usize = cs.iter().map(|c| digest(c.other, &d).as_ref().len()).sum(); // SHA-1
    // an `Option`'s value, `None` on one way
    let o: Option<D> = if n(2) > 0 { Some(&SHA384) } else { None };
    let _ = o.map(|a| digest(a, &d)); // SHA-384
    let _ = o.map_or(0, |a| digest(a, &d).as_ref().len()); // SHA-384
    // a `Result`'s value
    let r: Result<D, ()> = if n(3) > 0 { Ok(&SHA512) } else { Err(()) };
    let _ = r.map(|a| digest(a, &d)); // SHA-512
    // the element replaced inside the closure before use
    let _: usize = a1.iter().map(|a| { let mut b: D = a; if n(4) > 0 { b = &SHA1; } digest(b, &d).as_ref().len() }).sum(); // SHA-256, SHA-384, SHA-1
    // a vector filled at run time
    let mut v: Vec<D> = Vec::new();
    if n(5) > 0 { v.push(&SHA1); } else { v.push(&SHA512); }
    v.into_iter().for_each(|a| { let _ = digest(a, &d); }); // SHA-1, SHA-512
}
