// round 15 (O1): writes through pointers the search used to miss (a holder made by a function, a
// closure run by a generic function, cells and locks handed to functions, a holder re-pointed
// through a lent part, a pointer stored through another, a returned parameter, a holder in a
// field, a type parameter): each gives the value written, or the unknown beside the others
use ring::digest::{Algorithm, SHA256, SHA512, digest};
use std::cell::{Cell, RefCell};
use std::sync::Mutex;

type A = &'static Algorithm;

// p1: a holder made by a function, written through by another
struct W1<'a> { r: &'a mut A }
fn wrap1(r: &mut A) -> W1<'_> { W1 { r } }
fn set1(w: W1) { *w.r = &SHA512; }
fn p1() { let mut a: A = &SHA256; let w = wrap1(&mut a); set1(w); let _ = digest(a, b"1"); }

// p3: a closure capturing `&mut` run by a generic function
fn run3<F: FnOnce()>(f: F) { f() }
fn p3() { let mut a: A = &SHA256; run3(|| a = &SHA512); let _ = digest(a, b"3"); }

// p4: a cell handed to a program function
fn set4(c: &Cell<A>) { c.set(&SHA512) }
fn p4() { let c = Cell::new(&SHA256 as A); set4(&c); let _ = digest(c.get(), b"4"); }

// p5: a RefCell written through `borrow_mut` in a program function
fn set5(c: &RefCell<A>) { *c.borrow_mut() = &SHA512 }
fn p5() { let c = RefCell::new(&SHA256 as A); set5(&c); let a = *c.borrow(); let _ = digest(a, b"5"); }

// p6: a holder's pointer re-pointed through a part lent to a function
struct H6<'a> { r: &'a mut A }
fn repoint6<'a>(slot: &mut &'a mut A, to: &'a mut A) { *slot = to }
fn p6() {
    let mut x: A = &SHA256;
    let mut y: A = &SHA256;
    {
        let mut h = H6 { r: &mut x };
        repoint6(&mut h.r, &mut y);
        *h.r = &SHA512;
    }
    let _ = digest(x, b"6x");
    let _ = digest(y, b"6y");
}

// p9: a pointer stored through another pointer, written later
struct S9<'a> { r: Option<&'a mut A> }
fn stash9<'a>(s: &mut S9<'a>, a: &'a mut A) { s.r = Some(a); }
fn p9() {
    let mut a: A = &SHA256;
    {
        let mut s = S9 { r: None };
        stash9(&mut s, &mut a);
        if let Some(r) = s.r { *r = &SHA512; }
    }
    let _ = digest(a, b"9");
}

// p10: a parameter's pointer returned whole
fn id10(s: &mut A) -> &mut A { s }
fn p10() { let mut a: A = &SHA256; *id10(&mut a) = &SHA512; let _ = digest(a, b"10"); }

// p12: a lock in a struct handed by shared borrow to a program function
struct C12 { m: Mutex<A> }
fn set12(c: &C12) { *c.m.lock().unwrap() = &SHA512 }
fn p12() { let c = C12 { m: Mutex::new(&SHA256) }; set12(&c); let a = *c.m.lock().unwrap(); let _ = digest(a, b"12"); }

// p13: a holder passed as a field of another value
struct W13<'a> { r: &'a mut A }
struct Outer13<'a> { w: W13<'a> }
fn set13(w: W13) { *w.r = &SHA512; }
fn p13() { let mut a: A = &SHA256; { let o = Outer13 { w: W13 { r: &mut a } }; set13(o.w); } let _ = digest(a, b"13"); }

// p14: a generic function writing through a value of a type parameter
trait Put { fn put(self); }
impl Put for &mut A { fn put(self) { *self = &SHA512; } }
fn apply14<T: Put>(t: T) { t.put() }
fn p14() { let mut a: A = &SHA256; apply14(&mut a); let _ = digest(a, b"14"); }

fn main() { p1(); p3(); p4(); p5(); p6(); p9(); p10(); p12(); p13(); p14(); }
