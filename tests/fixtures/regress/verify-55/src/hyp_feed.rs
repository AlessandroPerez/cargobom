use crate::hyp_types::Hasher8;
use sha2::digest::DynDigest;

pub fn feed8(h: &mut Hasher8, d: &[u8]) {
    h.update(d);
}

pub fn feed8i(h: &mut (impl DynDigest + ?Sized), d: &[u8]) {
    h.update(d);
}
