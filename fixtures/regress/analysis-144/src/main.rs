// audit 13 probe pr1: predicates and error sides in the value search and the unknown check
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn res(i: usize) -> Result<&'static Digest, String> { if arg(i).is_empty() { Ok(&SHA256) } else { Err(arg(i)) } }

fn main() {
    let d = arg(0).into_bytes();
    let o: Option<u8> = arg(1).parse().ok();
    let a1 = o.ok_or(&SHA512).err().unwrap_or(&SHA256);
    let _ = digest(a1, &d);
    let a2: &Digest = res(2).map_err(|_| &SHA384).unwrap_or_else(|e| e);
    let _ = digest(a2, &d);
    let cap: &'static Digest = &SHA512;
    let a3 = None.or_else(|| Some(cap)).unwrap_or(&SHA1);
    let _ = digest(a3, &d);
    let p: Option<&'static Digest> = if arg(3).is_empty() { Some(&SHA256) } else { None };
    let a4 = p.filter(|x| x.output_len() > 40 || cap.output_len() > 0).unwrap_or(&SHA384);
    let _ = digest(a4, &d);
    let a5 = p.inspect(|_| { let _ = cap; }).unwrap_or(&SHA384);
    let _ = digest(a5, &d);
    let r: Result<&'static Digest, &'static Digest> = if arg(4).is_empty() { Ok(&SHA256) } else { Err(&SHA1) };
    let a6 = r.unwrap_or_else(|e| e);
    let _ = digest(a6, &d);
    let a7 = r.err().unwrap_or(&SHA384);
    let _ = digest(a7, &d);
    let a8 = p.ok_or(&SHA1).unwrap_or_else(|e| e);
    let _ = digest(a8, &d);
}
