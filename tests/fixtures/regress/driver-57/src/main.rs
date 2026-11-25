use sha2::Digest;

pub enum Kind {
    Plain,
    Timed(u8),
}

pub trait Shape {
    const KIND: Kind;
}

pub struct Flat;
pub struct Clocked;

impl Shape for Flat {
    const KIND: Kind = Kind::Plain;
}

impl Shape for Clocked {
    const KIND: Kind = Kind::Timed(3);
}

// reached only from the arm no instance of the program takes
fn stamped(n: Option<u8>, d: &[u8]) -> Vec<u8> {
    let mut h = sha2::Sha512::new();
    h.update([n.unwrap_or_default()]);
    h.update(d);
    h.finalize().to_vec()
}

fn run<T: Shape>(d: &[u8]) -> Vec<u8> {
    match T::KIND {
        // (`Some` as a function: a constructor, of a generic type)
        Kind::Timed(n) => [n, n]
            .into_iter()
            .map(Some)
            .flat_map(|n| stamped(n, d))
            .collect(),
        Kind::Plain => sha2::Sha256::digest(d).to_vec(),
    }
}

fn main() {
    let input = std::env::args().nth(1).unwrap_or_default();
    println!("{:?}", run::<Flat>(input.as_bytes()));
}
