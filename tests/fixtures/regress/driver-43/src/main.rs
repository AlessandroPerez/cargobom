use std::collections::HashMap;

use sha2::Digest;
use sha2::digest::Output;

type H<D> = fn(Vec<u8>) -> Output<D>;
type M = fn(Vec<u8>) -> md5::Digest;

// The function itself is the static's value, or in its array: no constant of the static's own.
static DIRECT: H<sha2::Sha224> = <sha2::Sha224 as Digest>::digest;
static ARRAY: [M; 1] = [md5::compute::<Vec<u8>>];

// Behind a reference: the table is a constant of the item's own.
static SLICE: &[H<sha2::Sha256>] = &[<sha2::Sha256 as Digest>::digest];
static PAIRS: &[(&str, H<sha2::Sha384>)] = &[("s", <sha2::Sha384 as Digest>::digest)];
const CONSTANT: &[H<sha2::Sha512>] = &[<sha2::Sha512 as Digest>::digest];

struct Entry {
    name: &'static str,
    run: H<sha2::Sha512_224>,
}

static ENTRIES: &[Entry] = &[Entry {
    name: "s",
    run: <sha2::Sha512_224 as Digest>::digest,
}];

struct Suite;

impl Suite {
    const RUN: &'static [H<sha2::Sha512_256>] = &[<sha2::Sha512_256 as Digest>::digest];
}

fn first<F: Copy>(t: &[F]) -> F {
    *t.iter().next().unwrap()
}

fn main() {
    let input = std::env::args().nth(1).unwrap_or_default().into_bytes();
    let mut n = DIRECT(input.clone()).len();
    let m = ARRAY[0];
    n += m(input.clone()).0.len();
    n += first(SLICE)(input.clone()).len();
    // (a table read into a map, the pointer looked up by name)
    let by_name: HashMap<&str, H<sha2::Sha384>> = PAIRS.iter().copied().collect();
    n += by_name["s"](input.clone()).len();
    n += first(CONSTANT)(input.clone()).len();
    let e = ENTRIES.iter().find(|e| e.name == "s").unwrap();
    n += (e.run)(input.clone()).len();
    n += first(Suite::RUN)(input).len();
    println!("{n}");
}
