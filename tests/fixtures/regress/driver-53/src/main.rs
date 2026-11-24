use sha2::{Digest, Sha256};

macro_rules! h {
    ($e:expr) => {
        Sha256::digest($e)
    };
}

/// The table, as the file holds it: one line.
fn table() -> [[u8; 32]; 150] {
    include!("table.rs")
}

fn main() {
    let t = table();
    // (a call on a line of its own, cited with its line as any)
    let all = Sha256::digest(t.concat());
    println!("{} {:x}", t.len(), all);
}
