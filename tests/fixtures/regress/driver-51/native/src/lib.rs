//! A crate with a C function of its own, which calls back into it by a symbol name.

use sha2::Digest;

unsafe extern "C" {
    fn native_entry(code: u32) -> u32;
}

// called by the C function only, under this name
#[unsafe(no_mangle)]
pub extern "C" fn native_report(code: u32) -> u32 {
    summed(code)
}

// called by the function above only
fn summed(code: u32) -> u32 {
    let d = sha2::Sha384::digest(code.to_le_bytes());
    u32::from(d[0])
}

pub fn enter(code: u32) -> u32 {
    unsafe { native_entry(code) }
}
