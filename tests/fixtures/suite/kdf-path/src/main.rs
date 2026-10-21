use ring::hkdf;

const LEGACY: bool = false;

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn main() {
    let alg = if LEGACY {
        hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY
    } else if std::env::args().count() > 1 {
        hkdf::HKDF_SHA384
    } else {
        hkdf::HKDF_SHA256
    };
    let salt = hkdf::Salt::new(alg, b"path-salt");
    let prk = salt.extract(b"input keying material");
    let info: [&[u8]; 1] = [b"ctx"];
    let mut out = [0u8; 32];
    prk.expand(&info, Len(32)).unwrap().fill(&mut out).unwrap();
    println!("{:02x?}", &out[..4]);
}
