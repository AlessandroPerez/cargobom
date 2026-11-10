// Calls the standard library makes into a crypto package where the code writes no call: `?`
// converts a `ParseIntError` into orion's error (`FromResidual::from_residual` runs orion's
// `From::from`), and `==` on two options compares orion's errors (`Option`'s `eq` runs the
// error's). Each is the package's error value made or compared, no operation: excused, not
// an unknown at the `?` or the `==`. `.into()` and `map_err(UnknownCryptoError::from)` name
// the conversion and are excused as well.
use orion::errors::UnknownCryptoError;

fn parse(s: &str) -> Result<u32, UnknownCryptoError> {
    let n: u32 = s.parse()?;
    Ok(n)
}

fn parse_two(a: &str, b: &str) -> Result<u32, UnknownCryptoError> {
    Ok(a.parse::<u32>()? + b.parse::<u32>().map_err(UnknownCryptoError::from)?)
}

fn convert(e: core::num::ParseIntError) -> UnknownCryptoError {
    e.into()
}

fn same(a: &Option<UnknownCryptoError>, b: &Option<UnknownCryptoError>) -> bool {
    a == b
}

fn main() {
    let a = parse("12").err();
    let b = parse_two("1", "x").err();
    let c = "y".parse::<u32>().map_err(convert).err();
    let key = orion::aead::SecretKey::default();
    let sealed = orion::aead::seal(&key, b"m").unwrap();
    println!("{} {} {}", same(&a, &b), same(&b, &c), sealed.len());
}
