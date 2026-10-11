use super::*;
use axum::{extract::ConnectInfo, routing::get, Router};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn transport_configuration_refuses_implicit_public_plaintext() -> TestResult {
    let mut config = ServerTransportConfig::default();
    for address in ["0.0.0.0:0", "[::]:0", "192.168.1.1:443"] {
        assert!(config.validate(address.parse()?).is_err());
    }
    config.validate("127.0.0.1:0".parse()?)?;
    config.validate("[::1]:0".parse()?)?;
    config.allow_plaintext = true;
    config.validate("0.0.0.0:0".parse()?)?;
    config.tls_cert = Some("cert.pem".into());
    assert!(config.validate("127.0.0.1:0".parse()?).is_err());
    config.tls_key = Some("key.pem".into());
    assert!(config.validate("127.0.0.1:0".parse()?).is_err());
    config.allow_plaintext = false;
    config.validate("0.0.0.0:443".parse()?)?;
    Ok(())
}

fn identity() -> TestResult<rcgen::CertifiedKey> {
    Ok(rcgen::generate_simple_self_signed(
        vec!["localhost".into()],
    )?)
}

fn connector(cert: Option<&rcgen::Certificate>) -> TestResult<tokio_rustls::TlsConnector> {
    let mut roots = rustls::RootCertStore::empty();
    if let Some(cert) = cert {
        roots.add(cert.der().clone())?;
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

async fn request(addr: SocketAddr, connector: &tokio_rustls::TlsConnector) -> TestResult<String> {
    let mut stream = connector
        .connect("localhost".try_into()?, TcpStream::connect(addr).await?)
        .await?;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    Ok(response)
}

#[test]
fn tls_identity_refuses_malformed_mismatched_and_multiple_keys() -> TestResult {
    let first = identity()?;
    let second = identity()?;
    for key in [
        "invalid".to_owned(),
        second.key_pair.serialize_pem(),
        first.key_pair.serialize_pem().repeat(2),
    ] {
        assert!(
            PreparedServerTransport::from_pem(first.cert.pem().as_bytes(), key.as_bytes()).is_err()
        );
    }
    assert!(PreparedServerTransport::from_pem(
        b"invalid",
        first.key_pair.serialize_pem().as_bytes()
    )
    .is_err());
    assert!(
        PreparedServerTransport::from_pem(b"", first.key_pair.serialize_pem().as_bytes()).is_err()
    );
    Ok(())
}

#[tokio::test]
async fn tls_preserves_peer_and_refuses_plaintext_untrusted_and_wrong_name() -> TestResult {
    let identity = identity()?;
    let prepared = PreparedServerTransport::from_pem(
        identity.cert.pem().as_bytes(),
        identity.key_pair.serialize_pem().as_bytes(),
    )?;
    let listener = prepared.bind("127.0.0.1:0".parse()?).await?;
    let addr = listener.local_addr()?;
    let router = Router::new().route(
        "/",
        get(|ConnectInfo(peer): ConnectInfo<CappedPeerAddr>| async move { peer.ip().to_string() }),
    );
    let server = tokio::spawn(async move {
        axum::serve(
            MaxConnListener::new(listener, 4),
            router.into_make_service_with_connect_info::<CappedPeerAddr>(),
        )
        .await
    });
    let trusted = connector(Some(&identity.cert))?;
    assert!(request(addr, &trusted).await?.contains("127.0.0.1"));
    assert!(request(addr, &connector(None)?).await.is_err());
    assert!(trusted
        .connect("wrong.example".try_into()?, TcpStream::connect(addr).await?)
        .await
        .is_err());
    let mut plain = TcpStream::connect(addr).await?;
    plain
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    let mut bytes = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(1), plain.read_to_end(&mut bytes)).await?;
    assert!(!String::from_utf8_lossy(&bytes).contains("200 OK"));
    server.abort();
    Ok(())
}

#[tokio::test]
async fn stalled_handshakes_are_concurrent_capped_and_release_on_timeout() -> TestResult {
    let identity = identity()?;
    let prepared = PreparedServerTransport::from_pem(
        identity.cert.pem().as_bytes(),
        identity.key_pair.serialize_pem().as_bytes(),
    )?;
    let mut listener = prepared.bind("127.0.0.1:0".parse()?).await?;
    listener.handshake_timeout = Duration::from_secs(2);
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        axum::serve(
            MaxConnListener::new(listener, 2),
            Router::new().route("/", get(|| async { "ok" })),
        )
        .await
    });
    let idle = TcpStream::connect(addr).await?;
    let trusted = connector(Some(&identity.cert))?;
    assert!(
        tokio::time::timeout(Duration::from_secs(1), request(addr, &trusted))
            .await??
            .contains("200 OK")
    );
    let idle_two = TcpStream::connect(addr).await?;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(50), request(addr, &trusted))
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(3), request(addr, &trusted))
            .await??
            .contains("200 OK")
    );
    drop((idle, idle_two));
    server.abort();
    Ok(())
}

#[tokio::test]
async fn tls_connection_drains_an_inflight_response_before_flush() -> TestResult {
    use std::sync::atomic::{AtomicBool, Ordering};
    let identity = identity()?;
    let prepared = PreparedServerTransport::from_pem(
        identity.cert.pem().as_bytes(),
        identity.key_pair.serialize_pem().as_bytes(),
    )?;
    let listener = prepared.bind("127.0.0.1:0".parse()?).await?;
    let addr = listener.local_addr()?;
    let entered = Arc::new(tokio::sync::Notify::new());
    let received = Arc::new(AtomicBool::new(false));
    let route_entered = entered.clone();
    let route_received = received.clone();
    let router = Router::new().route(
        "/",
        get(move || {
            let entered = route_entered.clone();
            let received = route_received.clone();
            async move {
                entered.notify_one();
                tokio::time::sleep(Duration::from_millis(50)).await;
                received.store(true, Ordering::SeqCst);
                "drained"
            }
        }),
    );
    let controller = ShutdownController::manual();
    let server = axum::serve(MaxConnListener::new(listener, 2), router)
        .with_graceful_shutdown(controller.signalled());
    let task = tokio::spawn(run_until_drained(
        server,
        controller.subscribe(),
        Duration::from_secs(1),
        async move {
            assert!(
                received.load(Ordering::SeqCst),
                "flush preceded response finalization"
            );
            Ok::<(), String>(())
        },
    ));
    let trusted = connector(Some(&identity.cert))?;
    let client = tokio::spawn(async move {
        request(addr, &trusted)
            .await
            .map_err(|error| error.to_string())
    });
    tokio::time::timeout(Duration::from_secs(1), entered.notified()).await?;
    controller.trigger();
    assert!(client.await??.contains("drained"));
    assert!(matches!(task.await??, DrainOutcome::Clean));
    Ok(())
}

#[test]
fn private_pem_errors_redact_debug_and_every_source() -> TestResult {
    let identity = identity()?;
    for input in [
        b"-----BEGIN PRIVATE KEY-----PRIVATE-MARKER\n".as_slice(),
        b"-----BEGIN PRIVATE-MARKER-----\n".as_slice(),
    ] {
        let error = PreparedServerTransport::from_pem(identity.cert.pem().as_bytes(), input)
            .err()
            .ok_or("malformed key accepted")?;
        let mut cause: Option<&dyn std::error::Error> = Some(&error);
        while let Some(error) = cause {
            let diagnostic = format!("{error} {error:?}");
            assert!(
                !diagnostic.contains("PRIVATE-MARKER"),
                "private input in error text"
            );
            assert!(
                !diagnostic.contains("80, 82, 73, 86, 65, 84, 69, 45, 77, 65, 82, 75, 69, 82"),
                "private input in error bytes"
            );
            cause = error.source();
        }
    }
    Ok(())
}
