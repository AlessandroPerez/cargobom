/* The code that is not Rust's: it calls back by name. */
unsigned native_report(unsigned code);

unsigned native_entry(unsigned code) {
    return native_report(code) + 1;
}
