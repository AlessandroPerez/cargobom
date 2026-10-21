// audit 12 probe s4: lock statics holding Option/Vec of program structs, thread_local RefCell
use ring::digest::{digest, Algorithm as Digest, SHA256, SHA384, SHA512};
use std::cell::RefCell;
use std::sync::Mutex;
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
#[derive(Clone, Copy)]
struct Cfg { h: &'static Digest }
static OPT: Mutex<Option<Cfg>> = Mutex::new(None);
static LIST: Mutex<Vec<Cfg>> = Mutex::new(Vec::new());
thread_local! { static TL: RefCell<Cfg> = const { RefCell::new(Cfg { h: &SHA256 }) }; }

fn main() {
    let d = arg(0).into_bytes();
    *OPT.lock().unwrap() = Some(Cfg { h: &SHA512 });
    let _ = digest(OPT.lock().unwrap().map(|c| c.h).unwrap_or(&SHA256), &d);
    LIST.lock().unwrap().push(Cfg { h: &SHA384 });
    let _ = digest(LIST.lock().unwrap()[0].h, &d);
    TL.with(|c| c.borrow_mut().h = &SHA512);
    let h = TL.with(|c| c.borrow().h);
    let _ = digest(h, &d);
}
