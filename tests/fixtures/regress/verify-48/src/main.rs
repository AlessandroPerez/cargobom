mod chains;
mod dispatch;
mod drivers;
mod sponge;

// pueue-lib: a module whose file a condition chooses; either file is `platform`
#[cfg_attr(not(target_os = "windows"), path = "unix.rs")]
#[cfg_attr(target_os = "windows", path = "windows.rs")]
mod platform;

use curve25519_dalek::Scalar;
use sha2::{Digest, Sha512};

fn main() {
    let input = std::env::args().nth(1).unwrap_or_default();
    let data = input.as_bytes();

    println!("{:x?}", sponge::wide(data));
    println!("{:x?}", sponge::narrow(data));
    println!("{:x?}", sponge::chained(data));
    println!("{:x?}", platform::socket_id(data));
    println!("{:x?}", dispatch::exchange(data));
    println!("{:x?}", chains::both(data));
    println!("{:x?}", drivers::install(data));

    // ed25519-zebra: the type argument of another crate's generic function, given by the
    // value passed, not written: SHA-512 is sha2's, the function curve25519-dalek's
    let k = Scalar::from_hash(Sha512::default().chain_update(data));
    println!("{:x?}", k.to_bytes());
}
