unsafe extern "C" {
    fn fixture_digest(first: u8) -> u8;
}

fn main() {
    let input = std::env::args().nth(1).unwrap_or_default();
    let first = input.bytes().next().unwrap_or(0);
    // the library's function, by its symbol
    let d = unsafe { fixture_digest(first) };
    println!("{d} {} {:x?}", driver_37::allocated(), driver_37::ring(first));
    println!("{}", driver_37::beside_async_closure(first));
}
