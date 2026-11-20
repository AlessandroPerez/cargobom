//! picky (`define_oid! { A => a => "..", B => b => "..", }`): a rule of a macro hands its
//! arguments on, one tuple at a time, to another rule of the same macro, which writes a
//! function and a closure for each. The code is cited at the invocation; the macro's line is in
//! the rule reached, and the items differ in the name the invocation gives each.

use std::sync::OnceLock;

use sha2::{Digest, Sha256};

macro_rules! define_tag {
    ($upper:ident => $lower:ident => $value:literal) => {
        pub const $upper: &str = $value;

        pub fn $lower() -> Vec<u8> {
            static TAG: OnceLock<Vec<u8>> = OnceLock::new();
            TAG.get_or_init(|| {
                Sha256::digest($upper).to_vec()
            }).clone()
        }
    };
    ( $( $upper:ident => $lower:ident => $value:literal, )+ ) => {
        $( define_tag! { $upper => $lower => $value } )+
    };
}

define_tag! {
    ALPHA => alpha => "alpha",
    BETA => beta => "beta",
}
