use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use sha2::{Digest, Sha256, Sha384};

pub struct Counting;

pub static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

fn count(layout: &Layout) {
    ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count(&layout);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

// the binary's allocator, declared in its library: the standard library's `__rust_alloc` is the
// function this attribute writes here
#[global_allocator]
static GLOBAL: Counting = Counting;

/// SHA-256, behind a symbol name: reachable from the binary, which calls it through an `extern`
/// declaration.
#[unsafe(no_mangle)]
pub extern "C" fn fixture_digest(first: u8) -> u8 {
    Sha256::digest([first])[0]
}

/// SHA-384, behind a symbol name nothing declares or calls: compiled, not reached.
#[unsafe(no_mangle)]
pub extern "C" fn fixture_unused(first: u8) -> u8 {
    Sha384::digest([first])[0]
}

pub fn allocated() -> usize {
    ALLOCATED.load(Ordering::Relaxed)
}

// heapless: a cell whose content is a projection over a const parameter. In the generic body
// the projection has no normal form to ask for; the driver takes it for what any instance may
// make it (it used to panic there, and the function's facts were lost).
pub trait Storage {
    type Buf: AsMut<[u8]>;
}

pub struct Inline<const N: usize>;

impl<const N: usize> Storage for Inline<N> {
    type Buf = [u8; N];
}

pub struct Ring<const N: usize> {
    cell: std::cell::UnsafeCell<<Inline<N> as Storage>::Buf>,
}

impl<const N: usize> Ring<N> {
    pub fn new(buf: [u8; N]) -> Self {
        Ring {
            cell: std::cell::UnsafeCell::new(buf),
        }
    }

    /// SHA-512/256 of what the ring holds, in a body generic over `N`.
    pub fn digest(mut self) -> Vec<u8> {
        let held = self.cell.get_mut();
        sha2::Sha512_256::digest(held.as_mut()).to_vec()
    }
}

pub fn ring(first: u8) -> Vec<u8> {
    Ring::<16>::new([first; 16]).digest()
}

// redis: an `async` closure in the value a call returns, beside a buffer the call is lent.
// `rustc_public` cannot convert the closure's type on the pinned nightly; the function's other
// code is read all the same (the driver used to give the whole function up where it asked
// whether the result holds a borrow of the buffer).
fn keep<F>(buf: &mut [u8], later: F) -> (usize, F) {
    buf[0] ^= 1;
    (buf.len(), later)
}

pub fn beside_async_closure(first: u8) -> u8 {
    let mut key = [first; 32];
    let (n, later) = keep(&mut key, async |x: u8| x.wrapping_add(1));
    let tag = sha2::Sha224::digest(&key[..n])[0];
    drop(later);
    tag
}
