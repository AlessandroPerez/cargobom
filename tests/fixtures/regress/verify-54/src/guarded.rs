use sha2::{Digest, Sha256};

// The attribute moves the function into one it awaits. That `.await` is the attribute's own
// code: the compiler has it at the attribute, whose text is no `.await`.
#[pm::guarded]
pub async fn checked(data: Vec<u8>) -> Vec<u8> {
    hash::<Sha256>(&data)
}

fn hash<D: Digest>(data: &[u8]) -> Vec<u8> {
    D::digest(data).to_vec()
}
