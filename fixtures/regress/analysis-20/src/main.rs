// Algorithms that reach a call from other functions, stored by data no entry point reaches
// (after the third audit round): rustls's `MlKem::start` is reachable through
// `DEFAULT_KX_GROUPS`, but its ML-KEM-1024 instance is listed only by `ALL_KX_GROUPS`. Here
// `Suite::hash` is reached through `DEFAULT`; SHA-512's suite only through `ALL`, which no entry
// point names: SHA-512 is present at the `digest` call, SHA-256 reachable.
use ring::digest;

pub trait Hasher: Sync {
    fn hash(&self, data: &[u8]) -> Vec<u8>;
}

pub struct Suite {
    alg: &'static digest::Algorithm,
}

impl Hasher for Suite {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        digest::digest(self.alg, data).as_ref().to_vec()
    }
}

static SHA256_SUITE: Suite = Suite { alg: &digest::SHA256 };
static SHA512_SUITE: Suite = Suite { alg: &digest::SHA512 };

pub static DEFAULT: &[&dyn Hasher] = &[&SHA256_SUITE];
pub static ALL: &[&dyn Hasher] = &[&SHA256_SUITE, &SHA512_SUITE];

fn main() {
    for h in DEFAULT {
        println!("{}", h.hash(b"data").len());
    }
}
