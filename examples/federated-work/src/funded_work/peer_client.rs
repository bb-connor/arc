//! Operator-pinned HTTPS delivery with a single absolute transport deadline.
use super::{checkpoint_files, evidence, peer_verifier as peer, verifier_operator::Enrollment};
use crate::common::{self, Result};
use chio_core_types::canonical_json_bytes;
use rustls::{
    crypto::aws_lc_rs, pki_types::ServerName, ClientConfig, ClientConnection, RootCertStore,
    StreamOwned,
};
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Cursor, Read, Write},
    net::{SocketAddr, TcpStream},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Endpoint {
    pub schema: String,
    pub origin: String,
    pub address: SocketAddr,
    pub ca_pem: String,
}

struct Deadline {
    stream: TcpStream,
    until: Instant,
}
impl Deadline {
    fn remaining(&self) -> io::Result<Duration> {
        self.until
            .checked_duration_since(Instant::now())
            .filter(|v| !v.is_zero())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "peer transport deadline exceeded")
            })
    }
}
impl Read for Deadline {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(bytes)
    }
}
impl Write for Deadline {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

pub(super) fn response(reader: &mut impl Read) -> Result<Vec<u8>> {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= 8192 {
            return Err("peer HTTP headers exceed limit".into());
        }
        let mut byte = [0];
        reader.read_exact(&mut byte)?;
        header.push(byte[0]);
    }
    let text = std::str::from_utf8(&header)?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    if lines.next() != Some("HTTP/1.1 200 OK") {
        return Err("peer did not return a decision".into());
    }
    let mut length = None;
    let mut content_type = false;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or("invalid peer HTTP header")?;
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err("invalid peer HTTP header name".into());
        }
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "content-length" => {
                let size: usize = value.parse()?;
                if length.is_some()
                    || size == 0
                    || size > super::wire::MAX_ARTIFACT_BYTES
                    || size.to_string() != value
                {
                    return Err("invalid peer response length".into());
                }
                length = Some(size);
            }
            "content-type" => {
                if content_type || value != "application/json" {
                    return Err("invalid peer response content type".into());
                }
                content_type = true;
            }
            "transfer-encoding" | "content-encoding" => {
                return Err("unsupported peer response encoding".into())
            }
            _ => {}
        }
    }
    if !content_type {
        return Err("missing peer content type".into());
    }
    let mut bytes = vec![0; length.ok_or("missing peer response length")?];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

pub(super) fn exchange(
    endpoint: &Endpoint,
    enrollment: &Enrollment,
    call: &peer::Call,
) -> Result<Vec<u8>> {
    let raw = canonical_json_bytes(call)?;
    peer::authenticate(&raw, enrollment, &endpoint.origin)?;
    let url = peer::origin(&endpoint.origin)?;
    if endpoint.schema != "chio.experimental.funded-verifier-endpoint.v1"
        || endpoint.ca_pem.len() > 64 * 1024
        || endpoint.address.port() != url.port_or_known_default().ok_or("HTTPS port missing")?
        || endpoint.address.ip().is_unspecified()
        || endpoint.address.ip().is_multicast()
    {
        return Err("invalid locally selected verifier endpoint".into());
    }
    let ca = crate::https::public_certificates(endpoint.ca_pem.as_bytes())?;
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut Cursor::new(ca)) {
        roots.add(cert?)?;
    }
    let mut tls = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name = ServerName::try_from(
        url.host_str()
            .ok_or("HTTPS host missing")?
            .trim_matches(['[', ']'])
            .to_owned(),
    )?;
    let until = Instant::now() + Duration::from_secs(30);
    let stream = TcpStream::connect_timeout(&endpoint.address, Duration::from_secs(5))?;
    let mut stream = StreamOwned::new(
        ClientConnection::new(Arc::new(tls), name)?,
        Deadline { stream, until },
    );
    let authority = &url[url::Position::BeforeHost..url::Position::AfterPort];
    write!(stream, "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", peer::ROUTE, authority, raw.len())?;
    stream.write_all(&raw)?;
    stream.flush()?;
    let raw = response(&mut stream)?;
    peer::verify_response(enrollment, call, &raw)?;
    Ok(raw)
}

pub fn send(
    endpoint: &Path,
    enrollment: &Path,
    call: &Path,
    output: &Path,
) -> Result<serde_json::Value> {
    let endpoint = evidence::read(endpoint)?;
    let enrollment = evidence::read(enrollment)?;
    let call = evidence::read(call)?;
    let raw = exchange(&endpoint, &enrollment, &call)?;
    let decision: super::verification::Decision = evidence::decode(&raw)?;
    checkpoint_files::write(output, &decision)?;
    Ok(serde_json::json!({"decisionSha256":common::digest(&decision.body)?}))
}
