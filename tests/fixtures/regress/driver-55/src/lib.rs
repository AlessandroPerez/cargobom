// A library generic over what a key of its dependency is parameterised by, reading the key
// from its bytes through the standard library's conversion (`SigningKey::<P>::try_from(b)`,
// `b.try_into()`): the function called is `core`'s, its type the crypto package's. It is the
// type's setup, as it is where the code fixes the parameter (`fixed`, `p256_key`), named by
// the family with the parameter open. A signature's bytes read the same way are an encoding.
use ecdsa::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use ecdsa::elliptic_curve::{AffinePoint, CurveArithmetic, FieldBytesSize};
use ecdsa::PrimeCurve;
use slh_dsa::{ParameterSet, Shake128f, Signature, SigningKey, VerifyingKey};

pub fn signing_key<P: ParameterSet>(bytes: &[u8]) -> Option<SigningKey<P>> {
    SigningKey::<P>::try_from(bytes).ok()
}

pub fn verifying_key<P: ParameterSet>(bytes: &[u8]) -> Option<VerifyingKey<P>> {
    VerifyingKey::<P>::try_from(bytes).ok()
}

pub fn into_key<P: ParameterSet>(bytes: &[u8]) -> Option<VerifyingKey<P>> {
    bytes.try_into().ok()
}

pub fn signature<P: ParameterSet>(bytes: &[u8]) -> Option<Signature<P>> {
    Signature::<P>::try_from(bytes).ok()
}

pub fn fixed(bytes: &[u8]) -> Option<VerifyingKey<Shake128f>> {
    VerifyingKey::<Shake128f>::try_from(bytes).ok()
}

pub fn ecdsa_key<C>(bytes: &[u8]) -> Option<ecdsa::VerifyingKey<C>>
where
    C: PrimeCurve + CurveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    ecdsa::VerifyingKey::<C>::try_from(bytes).ok()
}

pub fn ecdsa_signature<C>(bytes: &[u8]) -> Option<ecdsa::Signature<C>>
where
    C: PrimeCurve,
    ecdsa::SignatureSize<C>: ecdsa::elliptic_curve::generic_array::ArrayLength<u8>,
{
    ecdsa::Signature::<C>::try_from(bytes).ok()
}

pub fn p256_key(bytes: &[u8]) -> Option<p256::ecdsa::VerifyingKey> {
    p256::ecdsa::VerifyingKey::try_from(bytes).ok()
}
