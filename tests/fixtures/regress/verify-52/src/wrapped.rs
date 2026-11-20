//! picky-asn1 (`asn1_wrapper! { auto struct ObjectIdentifierAsn1(..), .. }`): one rule of a
//! macro leaves a trait's impl to a derive, another writes it out. The impl for a type an
//! `auto` invocation names is that invocation's, whatever of the impl's path the other rule's
//! text holds.

use pm::Tagged;

pub trait Tagged {
    fn tag_bytes(&self) -> Vec<u8>;
}

macro_rules! wrapper {
    (auto struct $name:ident) => {
        #[derive(Tagged)]
        pub struct $name(pub Vec<u8>);
    };
    (plain struct $name:ident) => {
        pub struct $name(pub Vec<u8>);

        impl Tagged for $name {
            fn tag_bytes(&self) -> Vec<u8> {
                self.0.clone()
            }
        }
    };
}

wrapper! { auto struct First }
wrapper! { auto struct Second }
wrapper! { plain struct Third }
