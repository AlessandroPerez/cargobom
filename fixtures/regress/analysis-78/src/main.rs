// round 12 regress (audit 11 probe gi4): generic instances named as function values, default bodies through pointers, trait objects in generic fns
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

trait Local { fn alg(&self) -> &'static Digest { &SHA1 } }
struct Over;
struct Def;
impl Local for Over { fn alg(&self) -> &'static Digest { &SHA256 } }
impl Local for Def {}
fn lpick<T: Local>(t: &T) -> &'static Digest { t.alg() }
fn apply(f: fn(&Over) -> &'static Digest, o: &Over) -> &'static Digest { f(o) }
fn apply_gen<T: Local>(f: fn(&T) -> &'static Digest, t: &T) -> &'static Digest { f(t) }
fn boxed<T: Local + 'static>(t: T) -> Box<dyn Local> { Box::new(t) }
fn via_dyn<T: Local + 'static>(t: T) -> &'static Digest { let b: Box<dyn Local> = Box::new(t); b.alg() }
static TABLE: [fn(&Over) -> &'static Digest; 1] = [lpick::<Over>];

fn main() {
    let d = arg(0).into_bytes();
    let f: fn(&Over) -> &'static Digest = lpick::<Over>;
    let _ = digest(f(&Over), &d);
    let _ = digest(apply(lpick::<Over>, &Over), &d);
    let _ = digest(apply_gen(lpick::<Over>, &Over), &d);
    let _ = digest(TABLE[0](&Over), &d);
    let _ = digest(boxed(Over).alg(), &d);
    let _ = digest(via_dyn(Over), &d);
    let g = <Over as Local>::alg;
    let _ = digest(g(&Over), &d);
    let h = Local::alg;
    let _ = digest(h(&Def), &d);
    let w = if arg(1).is_empty() { lpick::<Over> as fn(&Over) -> &'static Digest } else { |_: &Over| &SHA384 };
    let _ = digest(w(&Over), &d);
}
