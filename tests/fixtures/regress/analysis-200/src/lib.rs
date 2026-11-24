// A library generic over what a key of its dependency is parameterised by (lupine-sign's
// `MlDsaSigningKey<P>` around `ml_dsa::SigningKey<P>`): its callers choose the parameter set,
// and the type says the family whatever they choose. `sign` and `verify` are ML-DSA, the set
// open, and `ecdsa_sign` is ECDSA on a curve not named; with the set written (`sign_65`,
// `p256_sign`) the name is whole. A mode is another matter: `cbc::Encryptor<C>` is AES-CBC for
// an AES cipher only, so `cbc_encrypt` is an encryption of unknown algorithm.
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockCipher, BlockEncryptMut, KeyInit, KeyIvInit};
use ecdsa::elliptic_curve::generic_array::ArrayLength;
use ecdsa::elliptic_curve::ops::Invert;
use ecdsa::elliptic_curve::subtle::CtOption;
use ecdsa::elliptic_curve::{CurveArithmetic, Scalar};
use ecdsa::hazmat::{DigestPrimitive, SignPrimitive};
use ecdsa::{PrimeCurve, SignatureSize};
use ml_dsa::signature::{Signer, Verifier};
use ml_dsa::{MlDsa65, MlDsaParams, Signature, SigningKey, VerifyingKey};

pub fn sign<P: MlDsaParams>(sk: &SigningKey<P>, msg: &[u8]) -> Signature<P> {
    sk.sign(msg)
}

pub fn verify<P: MlDsaParams>(vk: &VerifyingKey<P>, msg: &[u8], sig: &Signature<P>) -> bool {
    vk.verify(msg, sig).is_ok()
}

pub fn sign_65(sk: &SigningKey<MlDsa65>, msg: &[u8]) -> Signature<MlDsa65> {
    sk.sign(msg)
}

pub fn ecdsa_sign<C>(sk: &ecdsa::SigningKey<C>, msg: &[u8]) -> ecdsa::Signature<C>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    ecdsa::signature::Signer::sign(sk, msg)
}

pub fn p256_sign(sk: &p256::ecdsa::SigningKey, msg: &[u8]) -> p256::ecdsa::Signature {
    ecdsa::signature::Signer::sign(sk, msg)
}

pub fn cbc_encrypt<C>(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8>
where
    C: BlockEncryptMut + BlockCipher + KeyInit,
{
    cbc::Encryptor::<C>::new_from_slices(key, iv)
        .unwrap()
        .encrypt_padded_vec_mut::<Pkcs7>(data)
}

pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    cbc::Encryptor::<aes::Aes128>::new_from_slices(key, iv)
        .unwrap()
        .encrypt_padded_vec_mut::<Pkcs7>(data)
}
