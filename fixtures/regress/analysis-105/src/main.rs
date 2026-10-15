// audit 12 probe c2: unknowns met only through dead callers: direct, through a live fn's return, through a dead fn's return
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn ha(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); }
fn hb(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); }
fn hc(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); }
fn live_unknown() -> &'static Digest { let mut a: &'static Digest = &SHA1; [0u8].iter().for_each(|_| a = &SHA384); a }
#[allow(dead_code)]
fn dead_unknown() -> &'static Digest { let mut a: &'static Digest = &SHA1; [0u8].iter().for_each(|_| a = &SHA512); a }
#[allow(dead_code)]
fn dead_a(d: &[u8]) { let mut a: &'static Digest = &SHA1; [0u8].iter().for_each(|_| a = &SHA384); ha(a, d); }
#[allow(dead_code)]
fn dead_b(d: &[u8]) { hb(live_unknown(), d); }
#[allow(dead_code)]
fn dead_c(d: &[u8]) { hc(dead_unknown(), d); }

fn main() {
    let d = arg(0).into_bytes();
    ha(&SHA256, &d);
    hb(&SHA256, &d);
    hc(&SHA256, &d);
    let _ = digest(live_unknown(), &d);
}
