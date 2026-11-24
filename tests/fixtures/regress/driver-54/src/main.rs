// A constant whose type is a parameter of a generic item, in a body read as the item wrote
// it: the closure in `sample` hashes with a reader and a length its function made, and on the
// way to where they come from the search meets `F::ZERO`, which the instance's arguments
// evaluate (`Base([0; 4])`) while the body still says its type is `F`. Reading the value by
// that type panicked in the compiler's conversion, and the closure was an item not analysed
// (six in arcis-compiler 0.16.0, whose `RescueDesc::<F, T>::sample_constants` this is). A
// value is read by its type in terms of the instance, and one without a layout is not read.
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

pub trait Field: Copy + PartialEq {
    const ZERO: Self;
    const NUM_BITS: u32;
    fn from_bytes(b: &[u8]) -> Self;
}

#[derive(Clone, Copy, PartialEq)]
pub struct Base([u64; 4]);

impl Field for Base {
    const ZERO: Self = Base([0; 4]);
    const NUM_BITS: u32 = 255;
    fn from_bytes(b: &[u8]) -> Self {
        Base([b[0] as u64 % 3, b[1] as u64, b[2] as u64, b[3] as u64])
    }
}

pub struct Desc<F: Field> {
    constants: Vec<F>,
}

impl<F: Field> Desc<F> {
    fn sample(m: usize) -> Self {
        let mut hasher = Shake256::default();
        let buffer_len = F::NUM_BITS.div_ceil(8) as usize + 16;
        hasher.update(b"encrypt everything, compute anything");
        let mut reader = hasher.finalize_xof();
        let mut constants: Vec<F> = (0..m)
            .map(|_| F::from_bytes(&reader.read_boxed(buffer_len)))
            .collect();
        while constants[0] == F::ZERO {
            let data = vec![F::ZERO; m]
                .into_iter()
                .map(|_| F::from_bytes(&reader.read_boxed(buffer_len)));
            constants = data.collect();
        }
        Desc { constants }
    }
}

fn main() {
    let d = Desc::<Base>::sample(4);
    println!("{}", d.constants.len());
}
