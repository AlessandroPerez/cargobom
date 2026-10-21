// W3: code generated into OUT_DIR, with a closure: its name must not carry the build path
fn main() {
    let out = std::env::var("OUT_DIR").unwrap();
    std::fs::write(
        format!("{out}/gen.rs"),
        "pub fn gen_hash(ds: &[&[u8]]) -> usize {\n    ds.iter().map(|d| ring::digest::digest(&ring::digest::SHA256, d).as_ref().len()).sum()\n}\n",
    )
    .unwrap();
}
