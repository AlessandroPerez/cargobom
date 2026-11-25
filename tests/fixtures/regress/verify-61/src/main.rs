#[derive(
    Clone,
    pm::Stamp
)]
struct Key(Vec<u8>);

#[pm::sealed]
struct Token(Vec<u8>);

fn main() {
    let key = Key(std::env::args().next().unwrap_or_default().into_bytes());
    println!("{:x?}", stamp!(&key.clone().0));
    let token = Token(std::env::args().next().unwrap_or_default().into_bytes());
    println!("{:x?}", seal!(&token.0));
}
