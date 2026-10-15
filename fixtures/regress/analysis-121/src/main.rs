// audit 13 probe a6: Option/Result combinators with function items (H2 variations), fallbacks given functions
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn fallback() -> &'static Digest { &SHA512 }
fn keep(x: &'static Digest) -> &'static Digest { x }
trait Pick { fn alg(&self) -> &'static Digest { &SHA1 } }
struct Fast;
impl Pick for Fast { fn alg(&self) -> &'static Digest { &SHA384 } }
struct Slow;
impl Pick for Slow {}
fn alg_of<T: Pick>(t: &T) -> &'static Digest { t.alg() }
struct Hold { h: &'static Digest }
impl Hold { fn get(&self) -> &'static Digest { self.h } }
fn wrap_ok(x: &'static Digest) -> Result<&'static Digest, String> { Ok(x) }

fn main() {
    let d = arg(0).into_bytes();
    let o: Option<&'static Digest> = if arg(1).is_empty() { None } else { Some(&SHA256) };
    let _ = digest(o.unwrap_or_else(fallback), &d);
    let _ = digest(o.or_else(|| Some(fallback())).unwrap(), &d);
    let mut g = o;
    let _ = digest(*g.get_or_insert_with(fallback), &d);
    let f = if arg(2).is_empty() { None } else { Some(Fast) };
    let _ = digest(f.as_ref().map(Pick::alg).unwrap_or(&SHA256), &d);
    let s = if arg(2).is_empty() { None } else { Some(Slow) };
    let _ = digest(s.as_ref().map(Pick::alg).unwrap_or(&SHA256), &d);
    let _ = digest(f.as_ref().map(alg_of).unwrap_or(&SHA256), &d);
    let h = if arg(3).is_empty() { None } else { Some(Hold { h: &SHA384 }) };
    let _ = digest(h.as_ref().map(Hold::get).unwrap_or(&SHA1), &d);
    let _ = digest(o.map(keep).map(keep).unwrap_or(&SHA1), &d);
    let r: Result<&'static Digest, String> = o.ok_or(String::new());
    let _ = digest(r.and_then(wrap_ok).unwrap_or(&SHA384), &d);
    let _ = digest(o.map_or_else(fallback, keep), &d);
    let _ = digest(o.as_ref().map(Clone::clone).unwrap_or(&SHA1), &d);
}
