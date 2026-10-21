// round 12 regress (audit 11 probe op1): Option/Result choices with closures and other combinators; crypto getters
use ring::aead::{self, LessSafeKey, UnboundKey, AES_256_GCM, CHACHA20_POLY1305};
use ring::digest::{digest, Algorithm as Digest, Context, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
use ring::hmac;

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

fn res(i: usize) -> Result<&'static Digest, String> { if i > 3 { Ok(&SHA384) } else { Err("no".into()) } }
fn opt(i: usize) -> Option<&'static Digest> { if i > 3 { Some(&SHA384) } else { None } }
fn ctx_alg(c: &Context) -> &'static Digest { c.algorithm() }
fn key_alg(k: &LessSafeKey) -> &'static aead::Algorithm { k.algorithm() }

fn main() {
    let d = arg(0).into_bytes();
    let i = arg(1).len();
    let v = vec![&SHA256];
    let _ = digest(v.get(i).copied().unwrap_or_else(|| &SHA512), &d);
    let _ = digest(v.get(i).map_or(&SHA512, |a| *a), &d);
    let _ = digest(v.get(i).map_or(&SHA512, |_| &SHA1), &d);
    let _ = digest(v.get(i).copied().or(Some(&SHA512)).unwrap(), &d);
    let _ = digest(v.get(i).copied().and_then(|_| Some(&SHA1)).unwrap_or(&SHA512), &d);
    let _ = digest(res(i).unwrap_or(&SHA512), &d);
    let _ = digest(res(i).unwrap_or_else(|_| &SHA512), &d);
    let _ = digest(opt(i).unwrap_or_default_alg(), &d);
    let _ = digest(opt(i).filter(|a| a.output_len() > 40).unwrap_or(&SHA256), &d);
    let _ = digest(if let Some(a) = opt(i) { a } else { &SHA1 }, &d);
    let _ = digest(opt(i).map(|_| &SHA512).unwrap_or(&SHA256), &d);
    let mut o: Option<&'static Digest> = None;
    let _ = digest(*o.get_or_insert(&SHA512), &d);
    let c1 = Context::new(&SHA384);
    let _ = digest(ctx_alg(&c1), &d);
    let c2 = Context::new(&SHA512);
    let c3 = c2.clone();
    let _ = digest(c3.algorithm(), &d);
    let dg = digest(&SHA256, &d);
    let _ = digest(dg.algorithm(), &d);
    let k = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &[0u8; 32]).unwrap());
    let k2 = LessSafeKey::new(UnboundKey::new(key_alg(&k), &[1u8; 32]).unwrap());
    let mut buf = d.clone();
    let _ = k2.seal_in_place_append_tag(aead::Nonce::assume_unique_for_key([0u8; 12]), aead::Aad::empty(), &mut buf);
    let uk = UnboundKey::new(if arg(2).is_empty() { &AES_256_GCM } else { &CHACHA20_POLY1305 }, &[2u8; 32]).unwrap();
    let a3 = uk.algorithm();
    let k3 = LessSafeKey::new(UnboundKey::new(a3, &[3u8; 32]).unwrap());
    let mut buf3 = d.clone();
    let _ = k3.seal_in_place_append_tag(aead::Nonce::assume_unique_for_key([0u8; 12]), aead::Aad::empty(), &mut buf3);
    let hk = hmac::Key::new(hmac::HMAC_SHA256, b"placeholder-not-a-key");
    let _ = hmac::sign(&hmac::Key::new(hk.algorithm(), b"placeholder-not-a-key"), &d);
    let _ = o;
}

trait DefaultAlg { fn unwrap_or_default_alg(self) -> &'static Digest; }
impl DefaultAlg for Option<&'static Digest> { fn unwrap_or_default_alg(self) -> &'static Digest { self.unwrap_or(&SHA256) } }
