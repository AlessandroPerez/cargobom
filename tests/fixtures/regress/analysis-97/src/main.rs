// audit 12 probe s5: thread_local statics of program structs read by field (const and lazy initializers)
use ring::digest::{digest, Algorithm as Digest, SHA256, SHA384};
use std::cell::{Cell, RefCell};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
#[derive(Clone, Copy)]
struct Cfg { h: &'static Digest }
thread_local! { static TC: RefCell<Cfg> = const { RefCell::new(Cfg { h: &SHA256 }) }; }
thread_local! { static TL: Cell<Cfg> = Cell::new(Cfg { h: &SHA384 }); }

fn main() {
    let d = arg(0).into_bytes();
    let a = TC.with(|c| c.borrow().h);
    let _ = digest(a, &d);
    let b = TL.with(|c| c.get().h);
    let _ = digest(b, &d);
}
