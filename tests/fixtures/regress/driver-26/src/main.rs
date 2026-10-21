// a type made a trait object in the program's code runs its methods only once such an object
// (of that trait, with those arguments) may be called: called through one, or handed to code the
// walk does not follow (here the standard library's). A closure only made one (`Box::new(|..|
// ..) as Box<dyn Fn(..)>`) too.
use ring::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
trait Hash { fn run(&self, d: &[u8]); }
trait Mac { fn run(&self, d: &[u8]); }
struct H1;
struct M1;
impl Hash for H1 { fn run(&self, d: &[u8]) { let _ = digest(&SHA256, d); } } // reachable
impl Mac for M1 { fn run(&self, d: &[u8]) { let _ = digest(&SHA1, d); } } // present: never called
struct Hold { cb: Box<dyn Fn(&[u8], u8)> }
fn main() {
    let d = std::env::args().next().unwrap_or_default().into_bytes();
    let h: &dyn Hash = &H1;
    h.run(&d);
    let _m: &dyn Mac = &M1;
    // stored, never called: present
    let _held = Hold { cb: Box::new(|x: &[u8], _n: u8| { let _ = digest(&SHA384, x); }) };
    // called through the box: reachable
    let called: Box<dyn Fn(&[u8])> = Box::new(|x: &[u8]| { let _ = digest(&SHA512, x); });
    called(&d);
}
