use sha2::{Digest, Sha256};

use super::{Ctx, H, Respond};

// `<Ctx<own::Sha256> as Respond>::respond`: `H` is the parent module's alias of the program's
// type, not of the `Sha256` this file imports
impl Respond for Ctx<H> {
    fn respond(&self, data: &[u8]) -> Vec<u8> {
        let mut out = self.0.finish(data);
        out.extend(Sha256::digest(data));
        out
    }
}
