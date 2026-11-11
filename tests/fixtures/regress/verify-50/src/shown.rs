//! pgp (`derive_more::Debug` on a type that holds a cx448 key): a procedural derive's code is
//! cited where the macro spans it, at the attribute, also where the type has a field of the
//! crypto package's type.

use pm::Show;

#[derive(Show)]
pub struct Holder {
    pub state: sha1_smol::Sha1,
}
