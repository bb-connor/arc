use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::{Readiness, ReadinessError};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn http(url: String) -> Readiness {
    Readiness::Http { url, bearer: Some("readiness-only-secret".to_string()) }
}

fn responder(
    listener: TcpListener,
    response: String,
    count: Arc<AtomicUsize>,
) -> tokio::task::JoinHandle<std::io::Result<()>> {
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await?;
            let mut request = [0_u8; 4096];
            let received = stream.read(&mut request).await?;
            if received == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            count.fetch_add(1, Ordering::SeqCst);
            stream.write_all(response.as_bytes()).await?;
        }
    })
}

#[tokio::test]
async fn readiness_never_follows_same_or_cross_origin_redirects() -> TestResult {
    for status in [301, 302, 303, 307, 308] {
        for same_origin in [true, false] {
            let source = TcpListener::bind("127.0.0.1:0").await?;
            let destination = TcpListener::bind("127.0.0.1:0").await?;
            let source_address = source.local_addr()?;
            let target_address = if same_origin {
                source_address
            } else {
                destination.local_addr()?
            };
            let source_count = Arc::new(AtomicUsize::new(0));
            let destination_count = Arc::new(AtomicUsize::new(0));
            let source_task = responder(
                source,
                format!(
                    "HTTP/1.1 {status} Redirect\r\nLocation: http://{target_address}/other\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                ),
                Arc::clone(&source_count),
            );
            let destination_task = responder(
                destination,
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
                Arc::clone(&destination_count),
            );
            let probe = http(format!("http://{source_address}/health")).prepare()?;
            let ready = probe.probe().await;
            source_task.abort();
            destination_task.abort();
            let _ = source_task.await;
            let _ = destination_task.await;
            assert!(!ready, "redirect status {status}, same origin {same_origin}");
            assert_eq!(source_count.load(Ordering::SeqCst), 1);
            assert_eq!(destination_count.load(Ordering::SeqCst), 0);
        }
    }
    Ok(())
}

#[tokio::test]
async fn readiness_caps_declared_and_streamed_response_bodies() -> TestResult {
    let oversized = 65_537;
    let body = "x".repeat(oversized);
    for headers in [
        format!("Content-Length: {oversized}\r\n"),
        "Transfer-Encoding: chunked\r\n".to_string(),
    ] {
        let payload = if headers.starts_with("Transfer-Encoding") {
            format!("{oversized:x}\r\n{body}\r\n0\r\n\r\n")
        } else {
            body.clone()
        };
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let count = Arc::new(AtomicUsize::new(0));
        let task = responder(
            listener,
            format!("HTTP/1.1 200 OK\r\n{headers}Connection: close\r\n\r\n{payload}"),
            Arc::clone(&count),
        );
        let probe = http(format!("http://{address}/health")).prepare()?;
        let ready = probe.probe().await;
        task.abort();
        let _ = task.await;
        assert!(!ready);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
    Ok(())
}

#[tokio::test]
async fn readiness_accepts_a_response_at_its_exact_byte_limit() -> TestResult {
    let size = 65_536;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = responder(
        listener,
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {size}\r\nConnection: close\r\n\r\n{}",
            "x".repeat(size)
        ),
        Arc::new(AtomicUsize::new(0)),
    );
    let ready = http(format!("http://{address}/health")).prepare()?.probe().await;
    task.abort();
    let _ = task.await;
    assert!(ready);
    Ok(())
}

#[test]
fn readiness_rejects_invalid_targets_and_headers_before_launch() {
    for url in [
        "not-a-url",
        "file:///tmp/readiness",
        "ftp://localhost/health",
        "http://operator:secret@localhost/health",
        "http://localhost/health#fragment",
        "http://localhost:0/health",
    ] {
        assert!(matches!(http(url.to_string()).prepare(), Err(ReadinessError::InvalidTarget)));
    }
    let invalid_header = Readiness::Http {
        url: "http://127.0.0.1/health".to_string(),
        bearer: Some("token\r\nInjected: true".to_string()),
    };
    let Err(error) = invalid_header.prepare() else {
        panic!("invalid bearer headers must reject before launch");
    };
    assert!(matches!(error, ReadinessError::Client(_)));
    assert!(!error.to_string().contains("Injected"));
}

#[test]
fn readiness_accepts_operator_selected_private_addresses() -> TestResult {
    for url in [
        "http://10.0.0.5/health",
        "http://172.16.0.5:8080/health",
        "http://192.168.1.10:8080/health",
        "http://[::ffff:192.168.1.10]:8080/health",
        "http://[fd00::5]:8080/health",
        "http://[::1]:8080/health",
        "https://EXAMPLE.com.:443/health",
    ] {
        http(url.to_string()).prepare()?;
    }
    Ok(())
}
