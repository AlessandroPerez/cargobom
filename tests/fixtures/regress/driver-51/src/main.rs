fn main() {
    let code = std::env::args().count() as u32;
    println!("{}", native::enter(code));
}
