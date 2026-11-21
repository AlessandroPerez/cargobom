// A path a macro writes with metavariables before its last name (sequoia-openpgp's
// `make_mode!` writes `$mode::$mode2::<aes::Aes128>::new(key, iv)`): the function the call is
// cited for is named after the path's last `::`, and no invocation names it.
macro_rules! keyed {
    ($f:ident, $outer:ident::$inner:ident) => {
        pub fn $f(key: &[u8], data: &[u8]) -> Vec<u8> {
            use hmac::Mac;
            let mut mac = $outer::$inner::<sha2::Sha256>::new_from_slice(key).expect("any length");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
    };
}

keyed!(tag, hmac::Hmac);
