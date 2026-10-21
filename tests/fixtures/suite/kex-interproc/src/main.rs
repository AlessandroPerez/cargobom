use p256::ecdh::{EphemeralSecret, SharedSecret};
use p256::PublicKey;
use rand_core::OsRng;

fn new_party() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::random(&mut OsRng);
    let public = secret.public_key();
    (secret, public)
}

fn agree(secret: &EphemeralSecret, peer: &PublicKey) -> SharedSecret {
    secret.diffie_hellman(peer)
}

fn main() {
    let (client, client_public) = new_party();
    let (server, server_public) = new_party();
    let a = agree(&client, &server_public);
    let b = agree(&server, &client_public);
    println!("{}", a.raw_secret_bytes() == b.raw_secret_bytes());
}
