use sha2::{Digest, Sha256};

struct Counter(u64);

impl Counter {
    fn update(&mut self, data: &[u8]) {
        self.0 += data.len() as u64;
    }
}

enum Sink {
    Sha(Sha256),
    Len(Counter),
}

// V1: the same call text at the same column on neighbouring lines, on receivers of different
// types: only the first is SHA-256. Moved one line down, the occurrence still finds `update`
// there; the line it records (`Sink::Sha(h)`, not `Sink::Len(h)`) tells them apart.
fn feed(sink: &mut Sink, data: &[u8]) {
    match sink {
        Sink::Sha(h) => h.update(data),
        Sink::Len(h) => h.update(data),
    }
}

fn main() {
    let mut a = Sink::Sha(Sha256::new());
    let mut b = Sink::Len(Counter(0));
    feed(&mut a, b"x");
    feed(&mut b, b"x");
    // V2: a line holding backquotes, in a comment after the call
    let d = Sha256::digest(b"y"); // the `y` input, see `feed`
    if let Sink::Len(c) = b {
        println!("{:x} {}", d, c.0);
    }
}
