fn main() {
    let input = std::env::args().nth(1).unwrap_or_default();
    let a = <older::sha256::Hash as older::Hash>::hash(input.as_bytes());
    let b = newer::sha256::Hash::hash(input.as_bytes());
    // (an operator on the package's type, which only the boundary check cites)
    println!("{:02x} {:02x}", a[..][0], b.to_byte_array()[0]);
}
