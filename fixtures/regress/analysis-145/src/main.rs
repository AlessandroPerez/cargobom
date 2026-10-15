// audit 13 probe pr2: error sides mapped to algorithms, with errors that carry no value
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn res2(i: usize) -> Result<&'static Digest, ()> { if arg(i).is_empty() { Ok(&SHA256) } else { Err(()) } }
fn to_alg(_e: ()) -> &'static Digest { &SHA512 }

fn main() {
    let d = arg(0).into_bytes();
    let a1: &Digest = res2(1).map_err(|_| &SHA384).unwrap_or_else(|e| e);
    let _ = digest(a1, &d);
    let a2: &Digest = res2(2).map_err(to_alg).unwrap_or_else(|e| e);
    let _ = digest(a2, &d);
    let r: Result<&'static Digest, &'static Digest> = if arg(3).is_empty() { Ok(&SHA256) } else { Err(&SHA1) };
    let a3 = r.ok().unwrap_or(&SHA384);
    let _ = digest(a3, &d);
    let a4 = match res2(4).map_err(|_| &SHA384) { Ok(a) => a, Err(e) => e };
    let _ = digest(a4, &d);
    let a5 = res2(5).or_else(|_| Ok::<_, ()>(&SHA1)).unwrap();
    let _ = digest(a5, &d);
    let a6 = res2(6).map_err(|_| &SHA384).err().unwrap_or(&SHA512);
    let _ = digest(a6, &d);
}
