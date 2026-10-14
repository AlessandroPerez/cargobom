// audit 10 probes vp6, vp10 (M9, M10): a pointer variable is bound where its scope says: a
// block's, a nested function's or a closure's own `let` is another variable, a self-copy names
// the one before, a macro's `let`, a method's result, `self`'s field, a tuple `let` over lines
use ring::digest::{self, Algorithm, Digest};

type HashFn = fn(&'static Algorithm, &[u8]) -> Digest;

const C: HashFn = digest::digest;

macro_rules! bind {
    ($n:ident) => {
        let $n: HashFn = digest::digest;
    };
}

struct Picker {
    n: usize,
}

impl Picker {
    fn new(n: usize) -> Self {
        Picker { n }
    }
    fn pick(&self) -> HashFn {
        if self.n > 1 { digest::digest } else { digest::digest }
    }
}

struct Holder {
    f: HashFn,
}

impl Holder {
    fn run(&self, d: &[u8]) -> usize {
        (self.f)(&digest::SHA1_FOR_LEGACY_USE_ONLY, d).as_ref().len()
    }
}

fn main() {
    let d = std::env::args().next().unwrap().into_bytes();
    let n = std::env::args().count();
    let h: HashFn = digest::digest;
    {
        let h: HashFn = digest::digest;
        let _ = h(&digest::SHA256, &d);
    }
    let _ = h(&digest::SHA384, &d);
    let g: HashFn = digest::digest;
    fn inner(d: &[u8]) -> usize {
        let g: HashFn = digest::digest;
        g(&digest::SHA1_FOR_LEGACY_USE_ONLY, d).as_ref().len()
    }
    let _ = inner(&d);
    let _ = g(&digest::SHA512, &d);
    let k: HashFn = digest::digest;
    let c = |x: &[u8]| {
        let k: HashFn = digest::digest;
        k(&digest::SHA512_256, x).as_ref().len()
    };
    let _ = c(&d);
    let _ = k(&digest::SHA256, &d);
    let f: HashFn = digest::digest;
    let f = f;
    let _ = f(&digest::SHA384, &d);
    bind!(m);
    let _ = m(&digest::SHA512, &d);
    let pk = Picker::new(n);
    let q = pk.pick();
    let _ = q(&digest::SHA512_256, &d);
    let ho = Holder { f: digest::digest };
    let _ = ho.run(&d);
    let _ = C(&digest::SHA1_FOR_LEGACY_USE_ONLY, &d);
    let (
        first_hash_function_pointer_with_a_much_longer_name,
        second_hash_function_pointer_with_a_long_name,
    ): (HashFn, HashFn) = (digest::digest, digest::digest);
    let _ =
        first_hash_function_pointer_with_a_much_longer_name(&digest::SHA1_FOR_LEGACY_USE_ONLY, &d);
    let _ = second_hash_function_pointer_with_a_long_name(&digest::SHA512_256, &d);
}
