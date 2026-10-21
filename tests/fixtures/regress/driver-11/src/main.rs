use ring::digest::{digest, Algorithm, SHA256, SHA384};

pub struct Table {
    pub alg: &'static Algorithm,
}
const fn sha256_table() -> Table {
    Table { alg: &SHA256 }
}
// D1: a static built by a const fn that names a ring static
static TABLE: Table = sha256_table();

// D2: the same through a plain static (control)
static TABLE2: Table = Table { alg: &SHA384 };

fn main() {
    println!("{:?} {:?}", digest(TABLE.alg, b"a"), digest(TABLE2.alg, b"b"));
}
