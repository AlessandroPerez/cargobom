// One invocation writes two functions that run the same operation (hpke's `define_mlkem!`
// writes a key's `ct_eq` and its `write_exact`, each calling `to_seed`): the operation is cited
// once, at the invocation, and each function is named where the macro writes it. A third is
// generic, and reached through a closure of a generic caller (cosmian_cover_crypt's
// `make_mlkem!` writes `dec` and a generic `enc`): its chain of instantiations starts at it,
// not at the function the occurrence names.
macro_rules! hashes {
    ($m:ident, $h:ty) => {
        pub mod $m {
            use sha2::Digest;

            pub fn once(d: &[u8]) -> Vec<u8> {
                <$h>::digest(d).to_vec()
            }

            pub fn twice(d: &[u8]) -> Vec<u8> {
                let first = <$h>::digest(d);
                <$h>::digest(first).to_vec()
            }

            pub fn spread(d: impl AsRef<[u8]>) -> Vec<u8> {
                <$h>::digest(d.as_ref()).to_vec()
            }
        }
    };
}

hashes!(wide, sha2::Sha384);

pub fn each<T: AsRef<[u8]>>(parts: &[T]) -> Vec<u8> {
    parts.iter().flat_map(|p| wide::spread(p)).collect()
}
