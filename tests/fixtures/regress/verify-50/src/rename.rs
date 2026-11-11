//! rustic-rs (suppaftp's `impl Read for AsyncRustlsStream`, `Read` being async-std's name for
//! `futures_io::AsyncRead`): an impl of a trait the file imports under the name another
//! package re-exports it by.

use sha2::Sha256;
use shim::Feed;

pub struct Tee(pub Sha256, pub usize);

impl Feed for Tee {
    fn update(&mut self, data: &[u8]) {
        self.1 += data.len();
        self.0.update(data);
    }
}
