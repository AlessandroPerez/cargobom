fn main() {
    let input = std::env::args().nth(1).unwrap_or_default().into_bytes();
    // (only one of the helper's two functions is called: the other is not in the program)
    println!("{}", helper::first(&input).len());
}
