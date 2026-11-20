//! tough (`RepositoryEditor::sign`): the line above an awaited call uses a variable bound to an
//! earlier awaited call of the same function, or to another type's function of that name. Such
//! a variable holds no future of the function: a position shifted to that line, at a `?` under
//! the `await`, is no place the function's body is run from.

use sha2::{Digest, Sha256};

pub struct Signed(pub Vec<u8>);

impl Signed {
    pub async fn new(data: &[u8], n: u8) -> Signed {
        let mut h = Sha256::new();
        h.update(data);
        h.update([n]);
        Signed(h.finalize().to_vec())
    }
}

pub async fn sign(data: &[u8]) -> Option<Vec<u8>> {
    let len = data.len();
    let mut sizes = Vec::new();
    sizes.push(len.checked_add(100)?);
    let one = Signed::new(data, 1).await;
    let kk = one.0.first().copied()?;
    let two = Signed::new(data, 2).await;
    Some([one.0, two.0, vec![kk, sizes.len() as u8]].concat())
}
