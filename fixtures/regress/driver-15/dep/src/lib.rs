use ring::digest::{Algorithm, SHA256};

pub struct Node {
    pub next: &'static Node,
    pub alg: Option<&'static Algorithm>,
}
// W1: two statics pointing at each other; only N1 names a ring static, N2 reaches it through N1
pub static N1: Node = Node { next: &N2, alg: Some(&SHA256) };
pub static N2: Node = Node { next: &N1, alg: None };

// W2: a const and a static of this (non-KB) crate naming ring statics
pub const ALG_C: &Algorithm = &ring::digest::SHA384;
pub static ALG_S: &Algorithm = &ring::digest::SHA512;
