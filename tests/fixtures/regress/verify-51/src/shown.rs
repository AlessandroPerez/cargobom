//! libp2p-noise (multiaddr's `Protocol` formatted by `write!`): a `Display` impl calling into a
//! crypto package the knowledge base does not model, reached through the standard library's
//! formatting arguments, which `write!` makes.

use std::fmt::{self, Display, Write};

pub struct Tag<'a>(&'a [u8]);

impl Display for Tag<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut h = sha1_smol::Sha1::new();
        h.update(self.0);
        write!(f, "{}", h.digest())
    }
}

pub fn render(data: &[u8]) -> String {
    let mut s = String::new();
    write!(&mut s, "{}", Tag(data)).unwrap();
    s
}
