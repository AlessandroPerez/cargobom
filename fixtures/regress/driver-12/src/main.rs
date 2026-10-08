use std::cmp::Ordering;
use std::mem::MaybeUninit;

use ring::digest::{SHA256, digest};

// D1: a const and a static reading the discriminant of a standard enum. `Ordering::Less = -1`
// is an anonymous const of `core` whose value needs no evaluation ("trivial"): rustc encodes
// neither its MIR nor its promoted constants, and asking for them panics inside the query.
const LESS: i8 = Ordering::Less as i8;
static GREATER: i8 = Ordering::Greater as i8;

#[derive(Clone, Copy, Default)]
struct Pair {
    a: u64,
    b: u32,
}

// D2: standard generic functions instantiated with local types. Their stored MIR was optimized
// when the standard library was built, with callees inlined: an inline `const { .. }` of an
// inlined callee is written in the callee's generics, not in those of the function it was
// inlined into.
#[allow(unnecessary_transmutes)]
fn std_generics() -> usize {
    let zeroed: Pair = unsafe { std::mem::zeroed() };
    let arr: [MaybeUninit<Pair>; 4] = [MaybeUninit::uninit(); 4];
    let copied: Pair = unsafe { std::mem::transmute_copy(&zeroed) };
    let read = unsafe { std::ptr::read(&copied) };
    let bytes: [u8; 8] = unsafe { std::mem::transmute(read.a) };
    let words: &[u32] = unsafe { [1u32, 2, 3, 4].align_to::<u32>().1 };
    let v: Vec<Pair> = Vec::with_capacity(2);
    let b = Box::new([Pair::default(); 2]);
    let s: [Pair; 3] = std::array::from_fn(|_| Pair::default());
    let m = std::mem::replace(&mut vec![1u8], vec![]);
    arr.len() + bytes.len() + words.len() + v.capacity() + b.len() + s.len() + m.len() + read.b as usize
}

fn main() {
    let d = digest(&SHA256, &[LESS as u8, GREATER as u8, std_generics() as u8]);
    println!("{:?}", d);
}
