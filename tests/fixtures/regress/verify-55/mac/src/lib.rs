// Macros of another crate than the ones that invoke them. Their paths are the invoking
// crate's (`sha2::..`, `hmac::..`, `ring::..`).

// A free function the invocation names. The call's path is qualified, with a metavariable in
// the type.
#[macro_export]
macro_rules! free_fn {
    ($name:ident, $h:ident) => {
        pub fn $name(d: &[u8]) -> Vec<u8> {
            <sha2::$h as sha2::Digest>::digest(d).to_vec()
        }
    };
}

// A method, invoked inside an impl the source writes: no item around it is a macro's.
#[macro_export]
macro_rules! method_in {
    ($name:ident, $h:ty) => {
        pub fn $name(&self) -> Vec<u8> {
            use sha2::Digest;
            <$h>::digest(&self.0).to_vec()
        }
    };
}

// An impl whole: its method is named in the macro.
#[macro_export]
macro_rules! whole_impl {
    ($t:ident, $h:ident) => {
        impl $t {
            pub fn whole(&self) -> Vec<u8> {
                use sha2::Digest;
                sha2::$h::digest(&self.0).to_vec()
            }
        }
    };
}

// A closure, in a function the source writes.
#[macro_export]
macro_rules! hasher {
    ($h:ident) => {
        |d: &[u8]| -> Vec<u8> {
            use sha2::Digest;
            sha2::$h::new_with_prefix(d).finalize().to_vec()
        }
    };
}

// Two functions that run the same operation, the second generic: one occurrence, two items,
// and a chain of instantiations that starts at the second.
#[macro_export]
macro_rules! pair {
    ($a:ident, $b:ident, $h:ident) => {
        pub fn $a(d: &[u8]) -> Vec<u8> {
            use sha2::Digest;
            sha2::$h::digest(d).to_vec()
        }

        pub fn $b<T: AsRef<[u8]>>(d: T) -> Vec<u8> {
            use sha2::Digest;
            sha2::$h::digest(d.as_ref()).to_vec()
        }
    };
}

// A macro that hands on to another of its crate.
#[macro_export]
macro_rules! outer {
    ($name:ident, $h:ident) => {
        pub fn $name(d: &[u8]) -> Vec<u8> {
            $crate::inner_digest!($h, d)
        }
    };
}

#[macro_export]
macro_rules! inner_digest {
    ($h:ident, $d:expr) => {
        <sha2::$h as sha2::Digest>::digest($d).to_vec()
    };
}

// An `async fn`, the function it awaits and the `await`.
#[macro_export]
macro_rules! async_fn {
    ($name:ident, $h:ident) => {
        pub async fn $name(d: Vec<u8>) -> Vec<u8> {
            async fn step(d: Vec<u8>) -> Vec<u8> {
                use sha2::Digest;
                sha2::$h::digest(&d).to_vec()
            }
            step(d).await
        }
    };
}

// A static table and the function that reads it.
#[macro_export]
macro_rules! table {
    ($name:ident, $read:ident, $($a:ident),+) => {
        pub static $name: &[&ring::digest::Algorithm] = &[$(&ring::digest::$a),+];

        pub fn $read(i: usize, d: &[u8]) -> Vec<u8> {
            ring::digest::digest($name[i % $name.len()], d).as_ref().to_vec()
        }
    };
}

// A constructor whose path has metavariables before its last name.
#[macro_export]
macro_rules! keyed {
    ($name:ident, $outer:ident::$inner:ident) => {
        pub fn $name(key: &[u8], d: &[u8]) -> Vec<u8> {
            use hmac::Mac;
            let mut m = $outer::$inner::<sha2::Sha256>::new_from_slice(key).expect("any length");
            m.update(d);
            m.finalize().into_bytes().to_vec()
        }
    };
}

// A value boxed as a trait object: the coercion is the macro's code, and is cited where the
// source invokes it.
#[macro_export]
macro_rules! boxed {
    ($h:ident) => {{
        let b: Box<dyn sha2::digest::DynDigest> = Box::new(<sha2::$h as sha2::Digest>::new());
        b
    }};
}

// A macro handed to another by name (kryptering's `dispatch_hash!(hash, do_sign)`): the
// invocation is written `$callback!(..)`, a metavariable where the macro's name is, and the
// invocation around it names the macro.
#[macro_export]
macro_rules! dispatch {
    ($n:expr, $callback:ident) => {
        match $n {
            0 => $callback!(sha2::Sha256),
            _ => $callback!(sha2::Sha512),
        }
    };
}

// Two calls one invocation writes, one of a less specific asset than the other (cms's
// `encrypt_block_mode!`): the key size asked of the block cipher, AES-128, beside the CBC
// encryptor made of it, AES-128-CBC. They are cited together, each with its own code.
#[macro_export]
macro_rules! cbc_with {
    ($alg:ident, $key:expr, $iv:expr, $data:expr) => {{
        use cbc::cipher::{BlockEncryptMut, KeyIvInit, KeySizeUser, block_padding::Pkcs7};
        if $key.len() != $alg::key_size() {
            return Vec::new();
        }
        let e = cbc::Encryptor::<$alg>::new_from_slices($key, $iv).expect("sizes checked");
        e.encrypt_padded_vec_mut::<Pkcs7>($data)
    }};
}
