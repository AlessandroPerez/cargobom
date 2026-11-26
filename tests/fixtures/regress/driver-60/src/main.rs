use std::cell::RefCell;
use std::io::Write;

use sha2::{Digest, Sha256};

type Format = fn(&mut dyn Write, &[u8]) -> Result<(), std::io::Error>;

fn with_buffer<F>(f: F)
where
    F: FnOnce(&RefCell<Vec<u8>>),
{
    thread_local! {
        static BUFFER: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(200));
    }
    BUFFER.with(f);
}

fn hashed(out: &mut dyn Write, data: &[u8]) -> Result<(), std::io::Error> {
    out.write_all(&Sha256::digest(data))
}

fn write_buffered(format: Format, data: &[u8], w: &mut dyn Write) -> Result<(), std::io::Error> {
    let mut result: Result<(), std::io::Error> = Ok(());
    with_buffer(|held| match held.try_borrow_mut() {
        Ok(mut buffer) => {
            (format)(&mut *buffer, data).unwrap_or_else(|e| eprintln!("formatting failed: {e}"));
            result = w.write_all(&buffer).inspect_err(|e| {
                eprintln!("writing failed: {e}");
            });
            buffer.clear();
        }
        Err(_) => {
            let mut other = Vec::<u8>::with_capacity(200);
            (format)(&mut other, data).unwrap_or_else(|e| eprintln!("formatting failed: {e}"));
            result = w.write_all(&other).inspect_err(|e| {
                eprintln!("writing failed: {e}");
            });
        }
    });
    result
}

fn main() {
    let mut out = Vec::new();
    write_buffered(hashed, b"some data", &mut out).expect("written");
    println!("{out:x?}");
}
