//! rustic-rs (`for item in tree_streamer`, an iterator of a crypto package): a `for` loop runs
//! its iterator's `next`; where that is an operation of a package the knowledge base does not
//! model (sharks deals the shares of a secret), it is cited at the `for`.

use sharks::Sharks;

pub fn deal(secret: &[u8]) -> usize {
    let sharks = Sharks(2);
    let mut total = 0;
    for share in sharks.dealer(secret).take(3) {
        total += Vec::from(&share).len();
    }
    total
}
