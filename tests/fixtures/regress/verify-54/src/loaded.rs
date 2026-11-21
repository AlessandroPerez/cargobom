use sha2::{Digest, Sha224};

pub struct Reader(pub Vec<u8>);

impl Reader {
    // A method and a closure in it: named here, in the module's file, not in the invocation
    // that declares the module.
    pub fn read(&self) -> Vec<u8> {
        let run = |d: &[u8]| {
            let mut h = Sha224::new();
            h.update(d);
            h.finalize().to_vec()
        };
        run(&self.0)
    }
}
