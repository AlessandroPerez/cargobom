// audit 13 probe a11: combinators given function pointers, closure variables, fn items in fallbacks (H2 variations)
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn keep(x: &'static Digest) -> &'static Digest { x }
fn fixed(_x: &'static Digest) -> &'static Digest { &SHA384 }
fn fallback() -> &'static Digest { &SHA512 }
fn fb_opt() -> Option<&'static Digest> { Some(&SHA384) }

fn main() {
    let d = arg(0).into_bytes();
    let o: Option<&'static Digest> = if arg(1).is_empty() { None } else { Some(&SHA256) };
    let f: fn(&'static Digest) -> &'static Digest = keep;
    let _ = digest(o.map(f).unwrap_or(&SHA1), &d);
    let k = |x: &'static Digest| x;
    let _ = digest(o.map(k).unwrap_or(&SHA1), &d);
    let c = |_x: &'static Digest| &SHA512;
    let _ = digest(o.map(c).unwrap_or(&SHA1), &d);
    let g: fn(&'static Digest) -> &'static Digest = if arg(2).is_empty() { keep } else { fixed };
    let _ = digest(o.map(g).unwrap_or(&SHA1), &d);
    let _ = digest(o.or_else(fb_opt).unwrap_or(&SHA1), &d);
    let r: Result<&'static Digest, ()> = o.ok_or(());
    let _ = digest(r.unwrap_or_else(|_| fallback()), &d);
    let _ = digest(r.map_or_else(|_| &SHA1, fixed), &d);
    let _ = digest(o.unwrap_or_else(|| fallback()), &d);
}
