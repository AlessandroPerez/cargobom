pub trait Tagged {
    fn tag(&self) -> Vec<u8>;
}

// The function that defines this derive is written again by an attribute macro on it
// (`pm/src/lib.rs`): the compiler has the derive defined at that attribute's line.
#[derive(pm::Tagged)]
pub struct Blob(pub Vec<u8>);

pub fn tag(data: &[u8]) -> Vec<u8> {
    Blob(data.to_vec()).tag()
}
