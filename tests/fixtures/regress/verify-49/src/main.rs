mod backend;
mod hashes;
mod keys;
mod scheme;

use backend::HashContext;
use hashes::HashImpl;

fn main() {
    let input = std::env::args().nth(1).unwrap_or_default();
    let data = input.as_bytes();

    let mut a = <hashes::Sha256 as HashImpl>::hasher();
    a.update(data);
    let mut b = <hashes::Sha512 as HashImpl>::hasher();
    b.update(data);
    println!("{:x?} {:x?}", a.complete(), b.complete());

    for key in [keys::Key::Short(backend::ShortKey), keys::Key::Long(backend::LongKey)] {
        println!("{:x?}", key.sign(data));
    }

    println!("{:?}", scheme::verify(data, data, input.len() % 2 == 0));
}
