use sha2::{Digest, Sha512};

pub struct Key(pub Vec<u8>);

impl Key {
    // The attribute rewrites the method into one returning a boxed `async move` block. The
    // compiler's span of that block is the `async` below, and its body's code is on the lines
    // after it: the block is the attribute's, and holds what the method it is on holds.
    #[pm::boxed]
    pub async fn sign(&self, msg: Vec<u8>) -> Vec<u8> {
        let d = Sha512::digest(&msg);
        [&self.0[..], &d[..]].concat()
    }
}
