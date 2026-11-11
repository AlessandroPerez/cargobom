//! russh: the impl of a trait for an enum that an attribute macro writes, each method calling
//! the variant's. The calls are cited at the attribute: on the enum the caller is a method of,
//! and naming the trait.

use enum_dispatch::enum_dispatch;
use sha2::{Digest, Sha256, Sha384};

#[enum_dispatch]
pub trait Kex {
    fn hash(&self, data: &[u8]) -> Vec<u8>;
}

pub struct Group<D>(std::marker::PhantomData<D>);

impl<D: Digest> Kex for Group<D> {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        D::digest(data).to_vec()
    }
}

#[derive(Clone, Copy)]
pub struct Plain;

impl Kex for Plain {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }
}

#[enum_dispatch(Kex)]
pub enum KexAlgorithm {
    Sha256(Group<Sha256>),
    Sha384(Group<Sha384>),
    Plain(Plain),
}

pub fn exchange(data: &[u8]) -> Vec<u8> {
    let algs: [KexAlgorithm; 3] = [
        Group::<Sha256>(std::marker::PhantomData).into(),
        Group::<Sha384>(std::marker::PhantomData).into(),
        Plain.into(),
    ];
    algs.iter().flat_map(|a| a.hash(data)).collect()
}
