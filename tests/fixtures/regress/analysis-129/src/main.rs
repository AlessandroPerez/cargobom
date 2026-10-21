// audit 13 probe a14: lazy statics read by field (closure results through helpers, branches), OnceLock get_or_init; one struct per static
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
use std::sync::{LazyLock, OnceLock};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
struct L1 { h: &'static Digest, legacy: &'static Digest }
struct L2 { h: &'static Digest, legacy: &'static Digest }
struct L3 { h: &'static Digest, legacy: &'static Digest }
struct L4 { h: &'static Digest, legacy: &'static Digest }
fn mk1() -> L1 { L1 { h: &SHA384, legacy: &SHA1 } }
static LC1: LazyLock<L1> = LazyLock::new(|| mk1());
static LC2: LazyLock<L2> = LazyLock::new(|| if arg(1).is_empty() { L2 { h: &SHA256, legacy: &SHA1 } } else { L2 { h: &SHA512, legacy: &SHA1 } });
fn pick() -> &'static Digest { &SHA512 }
static LC3: LazyLock<L3> = LazyLock::new(|| L3 { h: pick(), legacy: &SHA1 });
static OC4: OnceLock<L4> = OnceLock::new();

fn main() {
    let d = arg(0).into_bytes();
    let _ = digest(LC1.h, &d);
    let _ = digest(LC2.h, &d);
    let _ = digest(LC3.h, &d);
    let _ = digest(LC3.legacy, &d);
    let c4 = OC4.get_or_init(|| L4 { h: &SHA384, legacy: &SHA1 });
    let _ = digest(c4.h, &d);
}
