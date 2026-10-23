// a library's generic functions run its dependencies' code whatever their type arguments: the
// dependency's functions they call (directly, through the dependency's own generic functions,
// in a closure) are reachable from the library's API, not only compiled
pub fn direct(data: impl AsRef<[u8]>) -> Vec<u8> {
    d30dep::hash224(data.as_ref())
}

pub fn nested<T: AsRef<[u8]>>(data: T) -> Vec<u8> {
    d30dep::hash_any(data)
}

pub fn in_closure<T: AsRef<[u8]>>(items: &[T]) -> Vec<Vec<u8>> {
    items.iter().map(|d| d30dep::hash256(d.as_ref())).collect()
}
