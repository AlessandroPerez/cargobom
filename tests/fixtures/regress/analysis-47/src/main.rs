use ring::digest;
use std::collections::HashMap;

// 1. a Vec built by pushes, indexed at run time
fn from_vec(i: usize, d: &[u8]) -> usize {
    let mut v: Vec<&'static digest::Algorithm> = Vec::new();
    v.push(&digest::SHA256);
    v.push(&digest::SHA384);
    digest::digest(v[i], d).as_ref().len()
}

// 2. a map built by inserts, read with get
fn from_map(k: &str, d: &[u8]) -> usize {
    let mut m: HashMap<&str, &'static digest::Algorithm> = HashMap::new();
    m.insert("a", &digest::SHA512);
    m.insert("b", &digest::SHA1_FOR_LEGACY_USE_ONLY);
    digest::digest(m.get(k).unwrap(), d).as_ref().len()
}

// 3. a supertrait object made from a subtrait object
trait Named {
    fn alg(&self) -> &'static digest::Algorithm;
}
trait Profile: Named {
    fn name(&self) -> &'static str;
}
struct P1;
impl Named for P1 {
    fn alg(&self) -> &'static digest::Algorithm { &digest::SHA512_256 }
}
impl Profile for P1 {
    fn name(&self) -> &'static str { "p1" }
}
fn upcast(p: &dyn Profile, d: &[u8]) -> usize {
    let n: &dyn Named = p;
    digest::digest(n.alg(), d).as_ref().len()
}

// 4. a default method one type overrides and the other does not
trait Hasher {
    fn alg(&self) -> &'static digest::Algorithm { &digest::SHA384 }
}
struct Plain;
struct Custom;
impl Hasher for Plain {}
impl Hasher for Custom {
    fn alg(&self) -> &'static digest::Algorithm { &digest::SHA256 }
}
fn defaulted(h: &dyn Hasher, d: &[u8]) -> usize {
    digest::digest(h.alg(), d).as_ref().len()
}

// 5. a generic type coerced, its method returning a field
trait Source {
    fn alg(&self) -> &'static digest::Algorithm;
}
struct Holder<T> {
    alg: &'static digest::Algorithm,
    _t: T,
}
impl<T> Source for Holder<T> {
    fn alg(&self) -> &'static digest::Algorithm { self.alg }
}
fn generic(s: &dyn Source, d: &[u8]) -> usize {
    digest::digest(s.alg(), d).as_ref().len()
}

// 6. a type the analysis does not name (a primitive) coerced beside a struct
trait Pick {
    fn alg(&self) -> &'static digest::Algorithm;
}
struct Fixed;
impl Pick for Fixed {
    fn alg(&self) -> &'static digest::Algorithm { &digest::SHA256 }
}
impl Pick for u8 {
    fn alg(&self) -> &'static digest::Algorithm { &digest::SHA512 }
}
fn partial(p: &dyn Pick, d: &[u8]) -> usize {
    digest::digest(p.alg(), d).as_ref().len()
}

fn main() {
    let n = std::env::args().count();
    let d = b"c1";
    let p: Box<dyn Profile> = Box::new(P1);
    let plain: Box<dyn Hasher> = Box::new(Plain);
    let custom: Box<dyn Hasher> = Box::new(Custom);
    let h: Box<dyn Source> = Box::new(Holder { alg: &digest::SHA1_FOR_LEGACY_USE_ONLY, _t: 1u8 });
    let f: Box<dyn Pick> = Box::new(Fixed);
    let b: Box<dyn Pick> = Box::new(3u8);
    println!("{} {}", partial(f.as_ref(), d), partial(b.as_ref(), d));
    println!(
        "{} {} {} {} {} {}",
        from_vec(n % 2, d),
        from_map(if n > 1 { "a" } else { "b" }, d),
        upcast(p.as_ref(), d),
        defaulted(plain.as_ref(), d),
        defaulted(custom.as_ref(), d),
        generic(h.as_ref(), d)
    );
}
