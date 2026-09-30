//! Authenticated loopback HTTPS surface for one pinned Docker adapter.
use super::*;
use rustls::{
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    ServerConfig, ServerConnection, StreamOwned,
};
use std::{
    fs::OpenOptions,
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::OpenOptionsExt,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerHttpsConfig {
    pub schema: String,
    pub bind: SocketAddr,
    pub certificate_der: Vec<u8>,
    pub private_key_file: PathBuf,
    pub bearer_file: PathBuf,
    pub docker: DockerAdapterConfig,
}

pub struct DockerHttpsServer {
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    bearer: Zeroizing<Vec<u8>>,
    adapter: DockerAdapter,
}

fn private_bytes(path: &std::path::Path, maximum: u64) -> Result<Zeroizing<Vec<u8>>> {
    if !path.is_absolute() {
        return Err(denied());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| denied())?;
    let metadata = file.metadata().map_err(|_| denied())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(denied());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| denied())?;
    if u64::try_from(bytes.len()).map_err(|_| denied())? != metadata.len() {
        return Err(denied());
    }
    Ok(bytes)
}

impl DockerHttpsConfig {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let bytes = private_bytes(path, 65_536)?;
        chio_core_types::canonical::UntrustedJsonText::from_wire(&bytes, 65_536)
            .and_then(|text| text.decode_signed())
            .map_err(|_| denied())
    }
}

impl DockerHttpsServer {
    pub fn bind(config: DockerHttpsConfig) -> Result<Self> {
        if config.schema != "chio.docker-https-adapter.v1"
            || !config.bind.ip().is_loopback()
            || config.bind.port() == 0
            || config.certificate_der.len() > 16_384
        {
            return Err(denied());
        }
        let adapter = DockerAdapter::new(config.docker)?;
        let bearer = private_bytes(&config.bearer_file, 64)?;
        if bearer.len() != 64
            || !bearer
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(denied());
        }
        let mut key = private_bytes(&config.private_key_file, 16_384)?;
        let mut tls =
            ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
                .with_safe_default_protocol_versions()
                .map_err(|_| denied())?
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(config.certificate_der)],
                    PrivatePkcs8KeyDer::from(std::mem::take(&mut *key)).into(),
                )
                .map_err(|_| denied())?;
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let listener = TcpListener::bind(config.bind).map_err(|_| unavailable())?;
        Ok(Self {
            listener,
            tls: Arc::new(tls),
            bearer,
            adapter,
        })
    }

    /// Bounded concurrency and one request per TLS connection. Closing any
    /// failed exchange preserves uncertainty in the original broker operation.
    pub fn serve(self) -> Result<()> {
        let server = Arc::new(self);
        let active = Arc::new(AtomicUsize::new(0));
        loop {
            let (stream, peer) = server.listener.accept().map_err(|_| unavailable())?;
            if !peer.ip().is_loopback()
                || active
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                        (count < 4).then_some(count + 1)
                    })
                    .is_err()
            {
                continue;
            }
            let active = active.clone();
            let selected = server.clone();
            std::thread::Builder::new()
                .name("docker-adapter".into())
                .spawn(move || {
                    struct Active(Arc<AtomicUsize>);
                    impl Drop for Active {
                        fn drop(&mut self) {
                            self.0.fetch_sub(1, Ordering::AcqRel);
                        }
                    }
                    let _active = Active(active);
                    let _result = selected.handle(stream);
                })
                .map_err(|_| unavailable())?;
        }
    }

    fn handle(&self, stream: TcpStream) -> Result<()> {
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(
                self.adapter.config.timeout_ms + 5_000,
            ))
            .ok_or_else(unavailable)?;
        let socket = DeadlineTcp { stream, deadline };
        let connection = ServerConnection::new(self.tls.clone()).map_err(|_| unavailable())?;
        let mut tls = StreamOwned::new(connection, socket);
        let bytes = read_request(&mut tls, &self.bearer)?;
        let command: DockerCommand =
            chio_core_types::canonical::UntrustedJsonText::from_wire(&bytes, 131_072)
                .and_then(|text| text.decode_signed())
                .map_err(|_| denied())?;
        let result = self.adapter.execute(&command)?;
        let body = canonical_json_bytes(&result)?;
        let head = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        tls.write_all(head.as_bytes())
            .and_then(|()| tls.write_all(&body))
            .and_then(|()| tls.flush())
            .map_err(|_| unavailable())?;
        tls.conn.send_close_notify();
        tls.flush().map_err(|_| unavailable())
    }
}

fn read_request(reader: &mut impl Read, bearer: &[u8]) -> Result<Vec<u8>> {
    let mut head = Zeroizing::new(Vec::new());
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= 16_384 {
            return Err(denied());
        }
        let mut byte = [0];
        reader.read_exact(&mut byte).map_err(|_| unavailable())?;
        head.push(byte[0]);
    }
    let text = std::str::from_utf8(&head).map_err(|_| denied())?;
    let mut lines = text.split("\r\n");
    if lines.next() != Some("POST /execute HTTP/1.1") {
        return Err(denied());
    }
    let mut headers = std::collections::BTreeMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or_else(denied)?;
        if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || headers
                .insert(name.to_ascii_lowercase(), value.trim())
                .is_some()
        {
            return Err(denied());
        }
    }
    let Some(token) = headers
        .get("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return Err(denied());
    };
    if token.len() != bearer.len()
        || !bool::from(token.as_bytes().ct_eq(bearer))
        || headers.get("content-type") != Some(&"application/json")
        || headers.contains_key("transfer-encoding")
        || headers.contains_key("expect")
        || headers.contains_key("upgrade")
    {
        return Err(denied());
    }
    let length = headers
        .get("content-length")
        .filter(|value| !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|length| (1..=131_072).contains(length))
        .ok_or_else(denied)?;
    let mut body = vec![0; length];
    reader.read_exact(&mut body).map_err(|_| unavailable())?;
    Ok(body)
}

struct DeadlineTcp {
    stream: TcpStream,
    deadline: Instant,
}
impl DeadlineTcp {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|value| !value.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "adapter deadline"))
    }
}
impl Read for DeadlineTcp {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(bytes)
    }
}
impl Write for DeadlineTcp {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}
