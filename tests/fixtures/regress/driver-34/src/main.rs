// uuid is no crypto package, but `Uuid::new_v4()` draws from a random generator (the
// operating system's, through getrandom, with uuid's default features) and `Uuid::new_v5`
// hashes with SHA-1: a wrapper (`[semantics] wrappers`). The calls uuid's code makes into the
// crypto set are cited where uuid makes them, and at the program's call into uuid too, as the
// calls the standard library makes for the program are: the draw by its generator, the hash
// (of a package the knowledge base does not model) as an operation of unknown algorithm. A
// call into uuid that reaches no crypto package (`parse_str`) is not cited.
use uuid::Uuid;

fn token() -> Uuid {
    Uuid::new_v4()
}

fn main() {
    let name = std::env::args().nth(1).unwrap_or_default();
    let a = token();
    let b = Uuid::new_v5(&Uuid::NAMESPACE_DNS, name.as_bytes());
    let c = Uuid::parse_str("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap();
    println!("{a} {b} {c}");
}
