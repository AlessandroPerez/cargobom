// See `cases.rs`: the trait is imported here under the name another module gives it.
use super::names::Dd;

pub fn fed(h: &mut dyn Dd, d: &[u8]) {
    h.update(d);
}
