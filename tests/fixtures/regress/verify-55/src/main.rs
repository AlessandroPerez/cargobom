mod cases;
mod names;

// One file in two crates (a package's library and its binary each declaring the same module):
// `dep`'s copy of the cases is compiled here as well, and each position in it is in an item of
// `dep` and in one of this crate.
#[path = "../dep/src/cases.rs"]
mod shared;

fn main() {
    let input = std::env::args().nth(1).unwrap_or_default().into_bytes();
    let n = cases::all(&input) + dep::cases::all(&input) + shared::all(&input) + names::all(&input);
    println!("{n}");
}
