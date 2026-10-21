// round 14: a pointer re-pointed in a loop into one of several parts (syn's `stmt_expr`):
// the search for what it points to is cut past its budget, not run to its depth bound
use ring::digest::{self, Algorithm, SHA256, SHA384, SHA512};

enum Node {
    A(Box<Pair>),
    B(Box<Pair>),
    C(Box<Single>),
    Leaf(&'static Algorithm),
}
struct Pair { l: Node, r: Node }
struct Single { x: Node }

fn deepest(root: &mut Node) {
    let mut t = root;
    loop {
        t = match t {
            Node::A(p) => &mut p.l,
            Node::B(p) => &mut p.r,
            Node::C(s) => &mut s.x,
            Node::Leaf(_) => break,
        };
    }
    if let Node::Leaf(a) = t {
        *a = &SHA512;
    }
}

fn first(n: &Node) -> &'static Algorithm {
    match n {
        Node::A(p) | Node::B(p) => first(&p.l),
        Node::C(s) => first(&s.x),
        Node::Leaf(a) => a,
    }
}

fn main() {
    let mut root = Node::A(Box::new(Pair { l: Node::Leaf(&SHA256), r: Node::Leaf(&SHA384) }));
    deepest(&mut root);
    let _ = digest::digest(first(&root), b"data");
}
