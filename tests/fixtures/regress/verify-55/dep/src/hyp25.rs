pub struct Wrap25<const K: usize>(pub [u8; K]);

const N25: usize = 4;

pub fn make25(d: &[u8]) -> Wrap25<{ N25 }> {
    use sha2::Digest;
    let h = sha2::Sha256::digest(d);
    Wrap25([h[0], h[1], h[2], h[3]])
}
