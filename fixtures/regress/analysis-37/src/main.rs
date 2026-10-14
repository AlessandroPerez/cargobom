// round 8: a standard trait's method on a protocol crate's type is that crate's code, not a
// crypto API: plaintext written into a rustls connection is no hash update (xh's tokio-rustls
// `self.session.writer().write(..)` was reported as SHA-256 and SHA-384 digests)
use std::io::Write;
use std::sync::Arc;

struct Session {
    conn: rustls::ClientConnection,
}

fn send(s: &mut Session, buf: &[u8]) -> usize {
    s.conn.writer().write(buf).unwrap_or(0)
}

fn main() {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let name = "example.com".try_into().unwrap();
    let conn = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
    let mut s = Session { conn };
    let _ = s.conn.writer().write_all(b"GET / HTTP/1.1\r\n\r\n");
    println!("{}", send(&mut s, b"x"));
}
