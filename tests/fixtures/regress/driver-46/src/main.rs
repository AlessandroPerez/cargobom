fn main() {
    let data = std::env::args().nth(1).unwrap_or_default().into_bytes();
    // a table of the crate's own functions, one the knowledge base names and one it does not:
    // an element is called, neither function is named here
    let (name, f) = md5::TABLE[0];
    println!("{name} {:x}", f(data.clone()));
    // a constant holding one
    let g = md5::FIRST;
    println!("{:x}", g(data.clone()));
    // a public field holding one; the private field's is called by the crate's own method
    let h = md5::OPEN.hash;
    println!("{:x}", h(data.clone()));
    println!("{:x}", md5::OPEN.run(data.clone()));
    // a static behind a static, and an `Option`
    let o = *md5::OUTER;
    println!("{:x}", o(data.clone()));
    if let Some(m) = md5::MAYBE {
        println!("{:x}", m(data.clone()));
    }
    // the program's own crate holding one, which its code names
    let p = picks::PICKED;
    println!("{:x}", p(data));
}
