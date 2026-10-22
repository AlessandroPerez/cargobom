use digest::{
    block_buffer::Eager,
    consts::U256,
    core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore},
    generic_array::typenum::{IsLess, Le, NonZero},
    HashMarker,
};
use hmac::{Hmac, Mac};

pub trait Tag {
    fn tag(&self, m: &[u8]) -> Vec<u8>;
}

impl<D> Tag for Hmac<D>
where
    D: CoreProxy,
    D::Core: HashMarker
        + BufferKindUser<BufferKind = Eager>
        + FixedOutputCore
        + digest::Reset
        + Default
        + Clone,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn tag(&self, m: &[u8]) -> Vec<u8> {
        let mut h = self.clone();
        h.update(m);
        h.finalize().into_bytes().to_vec() // HMAC of the caller's hash
    }
}
