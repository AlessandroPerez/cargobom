//! jj-core's `id_type!`: a macro defined under one name and used under another a `use` gives
//! it. The struct it defines derives `ContentHash`: the derive's call for the field is cited
//! in the macro's body, at the struct's line.

#[doc(hidden)]
#[macro_export]
macro_rules! _id_type {
    (   $(#[$attr:meta])*
        $vis:vis $name:ident
    ) => {
        $(#[$attr])*
        #[derive($crate::content_hash::ContentHash, PartialEq, Eq, PartialOrd, Ord, Clone)]
        $vis struct $name(Vec<u8>);
    };
}

pub use _id_type as id_type;
