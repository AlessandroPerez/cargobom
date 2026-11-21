// One invocation writes two functions that run the same operation (hpke's `define_mlkem!`
// writes a key's `ct_eq` and its `write_exact`, each calling `to_seed`): the operation is cited
// once, at the invocation, and each function is named where the macro writes it.
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
        }
    };
}

hashes!(wide, sha2::Sha384);
