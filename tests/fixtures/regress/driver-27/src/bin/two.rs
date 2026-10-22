// SHA-384 at the library's `shared`: bin two
fn main() {
    let d = std::env::args().next().unwrap_or_default().into_bytes();
    let _ = d27::shared(&ring::digest::SHA384, &d);
}
