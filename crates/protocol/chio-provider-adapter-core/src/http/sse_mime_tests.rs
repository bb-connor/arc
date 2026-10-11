#![allow(clippy::unwrap_used)]
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const VALID_SSE: &[u8] =
    b": comment\r\nevent: response.created\r\ndata: {\"type\":\"response.created\"}\r\n\r\n";

async fn endpoint(
    headers: Vec<u8>,
    body: Option<Vec<u8>>,
) -> (
    String,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<Vec<u8>>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (release, released) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut request = Vec::new();
        let mut buffer = [0; 1024];
        while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            let count = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            assert!(count > 0, "client closed before sending HTTP headers");
            request.extend_from_slice(&buffer[..count]);
            assert!(request.len() <= 16 * 1024, "fixture request exceeded bound");
        }
        socket.write_all(&headers).await.unwrap();
        if let Some(body) = body {
            if let Err(error) = socket.write_all(&body).await {
                assert!(
                    matches!(
                        error.kind(),
                        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                    ),
                    "unexpected fixture body-write failure: {error}"
                );
            }
        } else {
            // Hold an advertised body open until the caller has observed the
            // transport result. The original collector must hit its own test
            // watchdog; a header rejection returns without reading this body.
            tokio::time::timeout(Duration::from_secs(5), released)
                .await
                .unwrap()
                .unwrap();
        }
        request
    });
    (format!("http://{address}"), release, server)
}

fn headers(status: u16, content_type: Option<&[u8]>, length: usize) -> Vec<u8> {
    let mut headers =
        format!("HTTP/1.1 {status} fixture\r\nContent-Length: {length}\r\nConnection: close\r\n")
            .into_bytes();
    if let Some(value) = content_type {
        headers.extend_from_slice(b"Content-Type: ");
        headers.extend_from_slice(value);
        headers.extend_from_slice(b"\r\n");
    }
    headers.extend_from_slice(b"\r\n");
    headers
}

fn assert_mime_rejection(result: Result<Vec<u8>, HttpTransportError>) {
    match result {
        Err(HttpTransportError::InvalidHeader { name, detail, .. }) => {
            assert_eq!(name, "content-type");
            assert_eq!(detail, "expected text/event-stream");
        }
        other => panic!("expected typed SSE MIME rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn wrong_missing_and_nontext_sse_mime_reject_even_valid_sse_bytes() {
    for content_type in [Some(&b"application/json"[..]), None, Some(&b"\xff"[..])] {
        let (url, _release, server) = endpoint(
            headers(200, content_type, VALID_SSE.len()),
            Some(VALID_SSE.to_vec()),
        )
        .await;
        let transport = HttpTransport::new(HttpTransportConfig::new(url)).unwrap();
        let result = transport.post_sse("/", b"{}").await;
        let request = server.await.unwrap();
        assert!(String::from_utf8(request)
            .unwrap()
            .to_ascii_lowercase()
            .contains("accept: text/event-stream"));
        if content_type == Some(&b"\xff"[..]) {
            assert!(
                matches!(
                    &result,
                    Err(HttpTransportError::InvalidHeader {
                        source: Some(cause),
                        ..
                    }) if cause.downcast_ref::<reqwest::header::ToStrError>().is_some()
                ),
                "native ToStrError was lost"
            );
        }
        assert_mime_rejection(result);
    }
}

#[tokio::test]
async fn invalid_sse_mime_refuses_headers_before_collecting_withheld_body() {
    for content_type in [Some(&b"application/json"[..]), None] {
        let (url, release, server) = endpoint(headers(200, content_type, 1024), None).await;
        let transport =
            HttpTransport::new(HttpTransportConfig::new(url).with_timeout(Duration::from_secs(3)))
                .unwrap();
        let result =
            tokio::time::timeout(Duration::from_millis(500), transport.post_sse("/", b"{}")).await;
        release.send(()).unwrap();
        server.await.unwrap();
        let result = result.unwrap_or_else(|_| {
            panic!("transport collected an invalid-MIME body instead of refusing its headers")
        });
        assert_mime_rejection(result);
    }
}

#[tokio::test]
async fn parameterized_sse_mime_preserves_exact_response_bytes() {
    for content_type in [
        b"text/event-stream; charset=utf-8".as_slice(),
        b"Text/Event-Stream ; charset=\"utf-8\"".as_slice(),
    ] {
        let (url, _release, server) = endpoint(
            headers(200, Some(content_type), VALID_SSE.len()),
            Some(VALID_SSE.to_vec()),
        )
        .await;
        let transport = HttpTransport::new(HttpTransportConfig::new(url)).unwrap();
        let actual = transport.post_sse("/", b"{}").await.unwrap();
        server.await.unwrap();
        assert_eq!(actual, VALID_SSE);
    }
}

#[tokio::test]
async fn non2xx_sse_status_keeps_precedence_without_body_collection() {
    let (url, release, server) =
        endpoint(headers(503, Some(b"application/json"), 1024), None).await;
    let transport = HttpTransport::new(HttpTransportConfig::new(url)).unwrap();
    let result =
        tokio::time::timeout(Duration::from_millis(500), transport.post_sse("/", b"{}")).await;
    release.send(()).unwrap();
    server.await.unwrap();
    assert!(matches!(
        result,
        Ok(Err(HttpTransportError::Status { code: 503 }))
    ));
}

#[tokio::test]
async fn sse_mime_keeps_declared_and_chunked_actual_byte_caps() {
    let (url, _release, server) = endpoint(
        headers(200, Some(b"text/event-stream"), 5),
        Some(b"12345".to_vec()),
    )
    .await;
    let transport =
        HttpTransport::new(HttpTransportConfig::new(url).with_max_response_bytes(4)).unwrap();
    let result = transport.post_sse("/", b"{}").await;
    server.await.unwrap();
    assert!(matches!(
        result,
        Err(HttpTransportError::ResponseTooLarge { maximum: 4 })
    ));
    let headers = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
    let (url, _release, server) =
        endpoint(headers, Some(b"3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n".to_vec())).await;
    let transport =
        HttpTransport::new(HttpTransportConfig::new(url).with_max_response_bytes(4)).unwrap();
    let result = transport.post_sse("/", b"{}").await;
    server.await.unwrap();
    assert!(matches!(
        result,
        Err(HttpTransportError::ResponseTooLarge { maximum: 4 })
    ));
}
