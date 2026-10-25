// A generic MAC whose binaries choose the hash (`tag::<Sha256>`): the instantiation cited for
// HMAC-SHA-256 chooses its SHA-256 component, which the verifier takes for that asset's.
use hmac::digest::block_buffer::Eager;
use hmac::digest::core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore};
use hmac::digest::typenum::{IsLess, Le, NonZero, U256};
use hmac::digest::HashMarker;
use hmac::{Hmac, Mac};

pub fn tag<D>(key: &[u8], msg: &[u8]) -> Vec<u8>
where
    D: CoreProxy,
    D::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    let mut m = <Hmac<D> as Mac>::new_from_slice(key).unwrap();
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}
