#[macro_export]
macro_rules! sha512_of {
    ($e:expr) => {
        ring::digest::digest(&ring::digest::SHA512, $e)
    };
}
