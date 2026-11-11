//! russh: ciphers as statics of a generic type, made trait objects in a table a `LazyLock`
//! builds. Each `&_AES_..` is where that type's methods are instantiated; the generic call in
//! `seal` is one position for the CTR and the CBC instances.

use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::LazyLock;

use aes::cipher::{
    BlockCipher, BlockEncryptMut, KeyInit, KeyIvInit, StreamCipher, block_padding::NoPadding,
};
use aes::{Aes128, Aes256};

pub trait Cipher {
    fn seal(&self, key: &[u8], iv: &[u8], data: &mut [u8]);
}

pub trait Stream {
    fn apply(key: &[u8], iv: &[u8], data: &mut [u8]);
}

pub struct CtrOf<C>(PhantomData<C>);
pub struct CbcOf<C>(PhantomData<C>);

impl<C> Stream for CtrOf<C>
where
    C: KeyIvInit + StreamCipher,
{
    fn apply(key: &[u8], iv: &[u8], data: &mut [u8]) {
        let mut c = C::new_from_slices(&key[..C::key_size()], iv).unwrap();
        c.apply_keystream(data);
    }
}

impl<C> Stream for CbcOf<C>
where
    C: BlockEncryptMut + BlockCipher + KeyInit,
{
    fn apply(key: &[u8], iv: &[u8], data: &mut [u8]) {
        let len = data.len();
        cbc::Encryptor::<C>::new_from_slices(&key[..C::key_size()], iv)
            .unwrap()
            .encrypt_padded_mut::<NoPadding>(data, len)
            .unwrap();
    }
}

fn run<S: Stream>(key: &[u8], iv: &[u8], data: &mut [u8]) {
    S::apply(key, iv, data)
}

pub struct Block<S>(PhantomData<S>);

impl<S: Stream> Cipher for Block<S> {
    fn seal(&self, key: &[u8], iv: &[u8], data: &mut [u8]) {
        run::<S>(key, iv, data)
    }
}

static _AES_128_CTR: Block<CtrOf<ctr::Ctr128BE<Aes128>>> = Block(PhantomData);
static AES_256_CTR: Block<CtrOf<ctr::Ctr128BE<Aes256>>> = Block(PhantomData);
static _AES_128_CBC: Block<CbcOf<Aes128>> = Block(PhantomData);

pub static CIPHERS: LazyLock<HashMap<&'static str, &(dyn Cipher + Send + Sync)>> =
    LazyLock::new(|| {
        let mut h: HashMap<&'static str, &(dyn Cipher + Send + Sync)> = HashMap::new();
        h.insert("aes128-ctr", &_AES_128_CTR);
        h.insert("aes256-ctr", &AES_256_CTR);
        h.insert("aes128-cbc", &_AES_128_CBC);
        h
    });
