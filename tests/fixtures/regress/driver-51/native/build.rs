fn main() {
    cc::Build::new().file("src/entry.c").compile("native_entry");
    println!("cargo:rerun-if-changed=src/entry.c");
}
