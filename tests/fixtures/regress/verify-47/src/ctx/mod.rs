//! vodozemac: aliases of one module used in the next, where the name an alias stands for means
//! something else (here `Sha256`: the program's type for `H`, sha2's in `resp.rs`).

mod resp;

use crate::own::Sha256;

type H = Sha256;

pub struct Ctx<T>(pub T);

pub trait Respond {
    fn respond(&self, data: &[u8]) -> Vec<u8>;
}

pub fn respond(data: &[u8]) -> Vec<u8> {
    let c: Ctx<H> = Ctx(Sha256 { seen: data.len() });
    c.respond(data)
}
