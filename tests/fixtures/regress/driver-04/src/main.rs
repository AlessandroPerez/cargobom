use ring::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384, SHA512};

// W1: a constructor in .init_array, kept by #[used]: runs before main
#[used]
#[unsafe(link_section = ".init_array")]
static INIT: extern "C" fn() = init;
extern "C" fn init() {
    let _ = digest(&SHA1_FOR_LEGACY_USE_ONLY, b"init");
}

// W2: trait-object upcasting
trait Base {
    fn h(&self) -> usize;
}
trait Sub: Base {
    fn s(&self) -> usize;
}
struct X;
impl Base for X {
    fn h(&self) -> usize {
        digest(&SHA384, b"x").as_ref().len()
    }
}
impl Sub for X {
    fn s(&self) -> usize {
        0
    }
}
fn w2(s: &dyn Sub) -> usize {
    let b: &dyn Base = s;
    b.h() + s.s()
}

// W3: Drop of a field
struct Inner;
impl Drop for Inner {
    fn drop(&mut self) {
        let _ = digest(&SHA512, b"drop");
    }
}
struct Outer {
    _i: Inner,
    _n: u8,
}

// W4: the KDF closure handed to ring's agree_ephemeral (a stop crate)
fn w4() -> usize {
    use ring::agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, X25519};
    let rng = ring::rand::SystemRandom::new();
    let my = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
    let peer = UnparsedPublicKey::new(&X25519, [9u8; 32]);
    agree_ephemeral(my, &peer, |km| digest(&SHA256, km).as_ref().len()).unwrap()
}

// W5: Display impl reached through format_args
struct Fp;
impl std::fmt::Display for Fp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", digest(&SHA256, b"fp"))
    }
}

fn main() {
    let x = X;
    let s: &dyn Sub = &x;
    let n = w2(s) + w4();
    let _o = Outer { _i: Inner, _n: 1 };
    println!("{n} {}", Fp);
}
