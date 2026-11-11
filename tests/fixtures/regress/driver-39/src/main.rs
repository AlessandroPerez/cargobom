use sha2::{Digest, Sha256, Sha384, Sha512};

trait Buf {
    fn chunk(&self) -> Vec<u8>;

    // a default method: in each type's vtable too
    fn checksum(&self) -> Vec<u8> {
        Sha512::digest(self.chunk()).to_vec()
    }
}

struct Slice<'a>(&'a [u8]);

impl Buf for Slice<'_> {
    fn chunk(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

struct Bytes(Vec<u8>);

impl Buf for Bytes {
    fn chunk(&self) -> Vec<u8> {
        digest_of(&self.0)
    }
}

// only the object's method calls it
fn digest_of(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

trait File {
    fn write_buf(&mut self, buf: Box<dyn Buf>) -> usize;
}

struct ReadOnly;

impl File for ReadOnly {
    // the object is dropped, never called
    fn write_buf(&mut self, _buf: Box<dyn Buf>) -> usize {
        Sha384::digest(b"refused").len()
    }
}

fn main() {
    let input = std::env::args().nth(1).unwrap_or_default().into_bytes();
    // a call of the method on a type that is no object: SHA-512 runs
    let direct = Slice(&input).checksum();
    let mut file: Box<dyn File> = Box::new(ReadOnly);
    println!("{} {}", direct.len(), file.write_buf(Box::new(Bytes(input))));
}
