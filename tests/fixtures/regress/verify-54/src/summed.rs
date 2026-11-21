pub trait Summed {
    fn sum(&self) -> Vec<u8>;
}

// The derive's call has the span of the field's type, which this macro writes: the compiler
// has it as `wrapper!`'s own code, at `$inner`, where nothing names a hash. The function it is
// in is the derive's.
macro_rules! wrapper {
    ($name:ident, $inner:ty) => {
        #[derive(pm::Summed)]
        pub struct $name(pub $inner);
    };
}

wrapper!(Bytes, Vec<u8>);
wrapper!(Text, String);

pub fn both(data: &[u8]) -> Vec<u8> {
    let mut out = Bytes(data.to_vec()).sum();
    out.extend(Text(String::from_utf8_lossy(data).into_owned()).sum());
    out
}
