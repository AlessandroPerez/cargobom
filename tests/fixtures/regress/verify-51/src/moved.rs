//! mongodb (`#[action_impl]`): an attribute macro on an impl moves `execute`'s body into a
//! method it writes for the same type (`Parse::run`); the code is cited where the text has it.

use pm::action;
use sha2::{Digest, Sha256};

pub trait Action {
    fn execute(self) -> Vec<u8>;
}

pub struct Parse(pub Vec<u8>);

#[action]
impl Action for Parse {
    fn execute(self) -> Vec<u8> {
        let h = Sha256::digest(&self.0);
        h.to_vec()
    }
}
