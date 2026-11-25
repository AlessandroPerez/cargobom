use derive_deftly::{Deftly, define_derive_deftly};
use sha2::{Digest, Sha256};

define_derive_deftly! {
    /// A fingerprint for a type that wraps bytes.
    Fingerprint for struct:

    impl $ttype {
        fn fingerprint(&self) -> Vec<u8> {
            Sha256::digest(&self.0).to_vec()
        }
    }
}

#[derive(Deftly)]
#[derive_deftly(Fingerprint)]
struct Key(Vec<u8>);

macro_rules! wrapper {
    ($name:ident) => {
        #[derive(Deftly)]
        #[derive_deftly(Fingerprint)]
        struct $name(Vec<u8>);
    };
}

wrapper!(Token);

fn main() {
    let key = Key(std::env::args().next().unwrap_or_default().into_bytes());
    println!("{:x?}", key.fingerprint());
    let token = Token(std::env::args().next().unwrap_or_default().into_bytes());
    println!("{:x?}", token.fingerprint());
}
