use std::sync::Arc;

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, KeyInit};
use rustls::crypto::cipher::{
    MessageEncrypter, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
};
use rustls::{ContentType, ProtocolVersion};

// the program's own record protection, as a custom provider writes one
struct Crypter<C>(C);

impl<C: AeadInPlace + Send + Sync> MessageEncrypter for Crypter<C> {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total = self.encrypted_payload_len(m.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total);
        payload.extend_from_chunks(&m.payload);
        let mut nonce = aes_gcm::aead::Nonce::<C>::default();
        let n = nonce.len();
        nonce[n - 8..].copy_from_slice(&seq.to_be_bytes());
        let tag = self
            .0
            .encrypt_in_place_detached(&nonce, &[], payload.as_mut())
            .map_err(|_| rustls::Error::EncryptError)?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(m.typ, m.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 16
    }
}

fn protect(key: &[u8; 16]) -> Box<dyn MessageEncrypter> {
    Box::new(Crypter(Aes128Gcm::new(key.into())))
}

fn main() {
    let input = std::env::args().nth(1).unwrap_or_default();
    let mut enc = protect(&[7u8; 16]);
    let msg = OutboundPlainMessage {
        typ: ContentType::ApplicationData,
        version: ProtocolVersion::TLSv1_3,
        payload: input.as_bytes().into(),
    };
    let sealed = enc.encrypt(msg, 0).map(|m| m.encode().len()).unwrap_or(0);
    // a connection, whose record layer starts with `<dyn MessageEncrypter>::invalid()`
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let conn = rustls::ClientConnection::new(Arc::new(config), "example.com".try_into().unwrap());
    println!("{sealed} {}", conn.is_ok());
}
