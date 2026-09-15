//! TLS transport for a separately provisioned provider. The HTTP backend is a
//! private Unix socket, so there is no plaintext TCP endpoint to bypass TLS.
use crate::common::*;
use base64::Engine;
use rustls::{crypto::aws_lc_rs, ServerConfig};
use std::{
    fs,
    io::{Cursor, Read},
    net::SocketAddr,
    os::unix::{fs::FileTypeExt, net::UnixListener},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tiny_http::Server;
use tokio::{runtime::Runtime, sync::Semaphore};
use tokio_rustls::TlsAcceptor;

pub struct HttpsConfig<'a> {
    pub bind: SocketAddr,
    pub origin: &'a str,
    pub certificate: &'a Path,
    pub private_key: &'a Path,
}

pub struct HttpsListener {
    pub server: Server,
    pub origin: String,
    pub runtime: Runtime,
}

fn read_pem(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 64 * 1024 {
        return Err("TLS material exceeds 64 KiB".into());
    }
    Ok(bytes)
}

fn origin(value: &str, bound: SocketAddr) -> Result<String> {
    let mut url = url::Url::parse(value)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || url.as_str().trim_end_matches('/') != value
    {
        return Err(
            "HTTPS origin must be canonical, without credentials, path, query or fragment".into(),
        );
    }
    // Port zero is only a local ephemeral-listener configuration. The published
    // origin always contains the actual bound port, never zero.
    if url.port() == Some(0) {
        url.set_port(Some(bound.port()))
            .map_err(|_| "invalid HTTPS port")?;
    }
    if url.port_or_known_default() != Some(bound.port()) {
        return Err("advertised HTTPS port differs from the bound listener".into());
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

pub fn enrollment(
    state: &Path,
    buyer: chio_core_types::PublicKey,
    endpoint: &str,
    ca_file: &Path,
) -> Result<serde_json::Value> {
    let identity = key(state)?;
    let peers: Peers = read(state.join("peers.json"))?;
    if peers.buyer != buyer || peers.provider != identity.public_key() {
        return Err("enrollment differs from the provider's configured peers".into());
    }
    let port = url::Url::parse(endpoint)?
        .port_or_known_default()
        .filter(|p| *p != 0)
        .ok_or("enrollment requires a concrete HTTPS port")?;
    origin(endpoint, SocketAddr::from(([127, 0, 0, 1], port)))?;
    let ca = public_certificates(&read_pem(ca_file)?)?;
    let body = serde_json::json!({
        "schema":"chio.example.https-enrollment.v2", "profile":WORK_PROFILE,
        "provider":identity.public_key(), "buyer":buyer, "origin":endpoint,
        "caPem":ca, "session":crate::provider::grant_session(state,buyer)?
    });
    Ok(serde_json::to_value(
        chio_core_types::receipt::lineage::SignedExportEnvelope::sign(body, &identity)?,
    )?)
}

fn public_certificates(bytes: &[u8]) -> Result<String> {
    for line in std::str::from_utf8(bytes)?.lines() {
        if line.starts_with("-----BEGIN ") && line != "-----BEGIN CERTIFICATE-----" {
            return Err("public enrollment accepts certificate blocks only".into());
        }
    }
    let mut roots = rustls::RootCertStore::empty();
    let mut public = String::new();
    for item in rustls_pemfile::read_all(&mut Cursor::new(bytes)) {
        let rustls_pemfile::Item::X509Certificate(certificate) = item? else {
            return Err("public enrollment cannot carry private keys or other PEM objects".into());
        };
        roots.add(certificate.clone())?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(certificate.as_ref());
        public.push_str("-----BEGIN CERTIFICATE-----\n");
        for line in encoded.as_bytes().chunks(64) {
            public.push_str(std::str::from_utf8(line)?);
            public.push('\n');
        }
        public.push_str("-----END CERTIFICATE-----\n");
    }
    if roots.is_empty() {
        return Err("enrollment requires valid TLS certificates".into());
    }
    // Re-encode only parsed certificates. Comments and unrelated file contents
    // must never be copied into a public, signed enrollment artifact.
    Ok(public)
}

pub fn listen(state: &Path, config: HttpsConfig<'_>) -> Result<HttpsListener> {
    let certificates = rustls_pemfile::certs(&mut Cursor::new(read_pem(config.certificate)?))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let private_key = rustls_pemfile::private_key(&mut Cursor::new(read_pem(config.private_key)?))?
        .ok_or("TLS private key is missing")?;
    let mut tls = ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)?;
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let listener = {
        let _entered = runtime.enter();
        let socket = if config.bind.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };
        socket.set_reuseaddr(true)?;
        socket.bind(config.bind)?;
        socket.listen(32)?
    };
    let advertised = origin(config.origin, listener.local_addr()?)?;
    let socket_path = state.join("https-backend.sock");
    match fs::symlink_metadata(&socket_path) {
        Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(&socket_path)?,
        Ok(_) => return Err("HTTPS backend path is not a socket".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    // The caller has acquired the exclusive durable authority before reaching
    // this point. The state directory remains private to the provider operator.
    let server = Server::from_listener(UnixListener::bind(&socket_path)?, None)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    runtime.spawn(async move {
        let slots = Arc::new(Semaphore::new(32));
        while let Ok((stream, _)) = listener.accept().await {
            let Ok(permit) = slots.clone().try_acquire_owned() else {
                drop(stream);
                continue;
            };
            let acceptor = acceptor.clone();
            let backend = socket_path.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let _ = forward(stream, acceptor, backend).await;
            });
        }
    });
    Ok(HttpsListener {
        server,
        origin: advertised,
        runtime,
    })
}

async fn forward(
    stream: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    backend: PathBuf,
) -> Result<()> {
    let mut tls = tokio::time::timeout(Duration::from_secs(5), acceptor.accept(stream)).await??;
    let mut http = tokio::net::UnixStream::connect(backend).await?;
    // TLS handshakes and connections are bounded separately. Neither a slow
    // peer nor unauthenticated TLS bytes can occupy an unbounded worker pool.
    tokio::time::timeout(
        Duration::from_secs(30),
        tokio::io::copy_bidirectional(&mut tls, &mut http),
    )
    .await??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_enrollment_rejects_keys_and_malformed_certificates() {
        for pem in [
            "",
            "unrelated private material",
            "-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAQID\n-----END ENCRYPTED PRIVATE KEY-----\n",
            "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
        ] {
            assert!(public_certificates(pem.as_bytes()).is_err());
        }
    }

    #[test]
    fn advertised_origin_cannot_change_scheme_or_route() -> Result<()> {
        let address = "127.0.0.1:8443".parse()?;
        assert_eq!(
            origin("https://provider.example:8443", address)?,
            "https://provider.example:8443"
        );
        assert_eq!(
            origin("https://localhost:0", address)?,
            "https://localhost:8443"
        );
        for value in [
            "http://provider.example:8443",
            "https://user@provider.example:8443",
            "https://provider.example:8443/path",
            "https://provider.example:8443?x=y",
            "https://provider.example:8443#part",
            "https://provider.example:8443/",
            "https://PROVIDER.example:8443",
            "https://provider.example:9000",
        ] {
            assert!(origin(value, address).is_err(), "{value}");
        }
        Ok(())
    }
}
