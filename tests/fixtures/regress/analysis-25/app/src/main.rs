// Layer 1 in a virtual workspace (fifth audit round): hmac is a build dependency of `app` and
// a normal one of hkdf, which `lib1` needs, so it is required, reached via `lib1 -> hkdf ->
// hmac`, not via the build edge `app -> hmac` met first. Also: a renamed dependency
// (`hashing`), optional ones a weak feature does not activate (blake3, argon2), a Windows-only
// one (md5), a dev-dependency (sha1).
use hashing::Digest;
fn main() {
    let d = hashing::Sha256::digest(b"x");
    println!("{:?} {:?}", d, lib1::derive(b"k"));
}
