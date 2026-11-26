use sha2::{Digest, Sha256};

// Invokes itself once for each token it is handed, and hashes when none is left.
macro_rules! each {
    () => {
        Sha256::digest(b"when no token is left")
    };
    ($first:tt $($rest:tt)*) => {
        each!($($rest)*)
    };
}

fn main() {
    // (a hundred tokens: the call is a hundred and one expansions deep)
    let digest = each!(
        x x x x x x x x x x x x x x x x x x x x
        x x x x x x x x x x x x x x x x x x x x
        x x x x x x x x x x x x x x x x x x x x
        x x x x x x x x x x x x x x x x x x x x
        x x x x x x x x x x x x x x x x x x x x
    );
    println!("{digest:x?}");
}
