//! Immutable server identity and per-connection, deadline-bounded TLS.
use crate::{private_pem, PemError};
use axum::serve::Listener;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::{
    future::Future,
    io,
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

/// Explicit transport posture. A public plaintext listener requires operator opt-in.
#[derive(Clone, Debug, Default)]
pub struct ServerTransportConfig {
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub allow_plaintext: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("TLS requires both certificate and private key files")]
    UnpairedIdentity,
    #[error("TLS and explicit plaintext are mutually exclusive")]
    ConflictingModes,
    #[error("non-loopback listeners require TLS or explicit allow-plaintext")]
    PlaintextDenied,
    #[error(
        "TLS identity exceeds its size limit or has an invalid number of certificates or keys"
    )]
    IdentityShape,
    #[error("invalid TLS PEM encoding")]
    Pem(#[from] PemError),
    #[error("invalid TLS identity or protocol configuration")]
    Tls(#[from] rustls::Error),
}

impl ServerTransportConfig {
    pub fn validate(&self, listen: SocketAddr) -> Result<(), TransportError> {
        match (&self.tls_cert, &self.tls_key) {
            (Some(_), None) | (None, Some(_)) => Err(TransportError::UnpairedIdentity),
            (Some(_), Some(_)) if self.allow_plaintext => Err(TransportError::ConflictingModes),
            (None, None) if !listen.ip().is_loopback() && !self.allow_plaintext => {
                Err(TransportError::PlaintextDenied)
            }
            _ => Ok(()),
        }
    }
}

/// Loaded once before startup side effects; connection failures never downgrade.
#[derive(Clone, Default)]
pub struct PreparedServerTransport {
    acceptor: Option<TlsAcceptor>,
}

impl PreparedServerTransport {
    pub fn from_pem(certificate: &[u8], private_key: &[u8]) -> Result<Self, TransportError> {
        if certificate.len() > 2 * 1024 * 1024 || private_key.len() > 64 * 1024 {
            return Err(TransportError::IdentityShape);
        }
        let certificates = CertificateDer::pem_slice_iter(certificate)
            .take(17)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| PemError::Framing)?;
        if certificates.is_empty() || certificates.len() > 16 {
            return Err(TransportError::IdentityShape);
        }
        let mut key = private_pem::private_key(private_key)?;
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        // Transfer wiping custody directly to the explicit AWS-LC key provider.
        // rustls CertifiedKey::from_der calls load_private_key first; AWS-LC
        // immediately wraps the owned DER in Zeroizing, including on error.
        .with_single_cert(
            certificates,
            std::mem::replace(&mut *key, PrivateKeyDer::Pkcs8(Vec::new().into())),
        )?;
        // The serving profile supports HTTP/1.1. Never advertise an unavailable protocol.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            acceptor: Some(TlsAcceptor::from(Arc::new(config))),
        })
    }

    pub fn is_tls(&self) -> bool {
        self.acceptor.is_some()
    }

    pub async fn bind(self, address: SocketAddr) -> io::Result<TransportListener> {
        Ok(TransportListener {
            inner: TcpListener::bind(address).await?,
            acceptor: self.acceptor,
            handshake_timeout: Duration::from_secs(5),
        })
    }
}

/// Accepting sockets never awaits a handshake. The outer MaxConnListener owns
/// the permit throughout handshake, request handling and shutdown.
pub struct TransportListener {
    inner: TcpListener,
    acceptor: Option<TlsAcceptor>,
    pub(crate) handshake_timeout: Duration,
}

impl TransportListener {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

impl Listener for TransportListener {
    type Io = TransportIo;
    type Addr = SocketAddr;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let (stream, peer) = Listener::accept(&mut self.inner).await;
        let state = match &self.acceptor {
            Some(acceptor) => Connection::Handshake(Box::pin(tokio::time::timeout(
                self.handshake_timeout,
                acceptor.accept(stream),
            ))),
            None => Connection::Plain(stream),
        };
        (TransportIo { state }, peer)
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

enum Connection {
    Plain(TcpStream),
    Handshake(Pin<Box<tokio::time::Timeout<tokio_rustls::Accept<TcpStream>>>>),
    Tls(Box<TlsStream<TcpStream>>),
    Closed,
}

pub struct TransportIo {
    state: Connection,
}
trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

impl TransportIo {
    fn poll_stream(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<&mut dyn Stream>> {
        if let Connection::Handshake(handshake) = &mut self.state {
            let result = std::task::ready!(handshake.as_mut().poll(cx));
            self.state = Connection::Closed;
            match result {
                Ok(Ok(stream)) => self.state = Connection::Tls(Box::new(stream)),
                Ok(Err(error)) => return Poll::Ready(Err(error)),
                Err(error) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, error)))
                }
            }
        }
        Poll::Ready(match &mut self.state {
            Connection::Plain(stream) => Ok(stream),
            Connection::Tls(stream) => Ok(stream.as_mut()),
            Connection::Closed | Connection::Handshake(_) => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "TLS connection closed",
            )),
        })
    }
}

impl AsyncRead for TransportIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(std::task::ready!(self.get_mut().poll_stream(cx))?).poll_read(cx, buf)
    }
}
impl AsyncWrite for TransportIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(std::task::ready!(self.get_mut().poll_stream(cx))?).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(std::task::ready!(self.get_mut().poll_stream(cx))?).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(std::task::ready!(self.get_mut().poll_stream(cx))?).poll_shutdown(cx)
    }
}
