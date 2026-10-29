#![allow(clippy::unwrap_used)]
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const REFUSED: &str = "urn:chio:error:transport:invalid-request-shape";

async fn refusal(base_url: String) -> HttpTransportError {
    let config = HttpTransportConfig::new(base_url).with_timeout(Duration::from_millis(500));
    match HttpTransport::new(config) {
        Err(error) => error,
        Ok(transport) => transport.post_json("/v1/chat", b"{}").await.unwrap_err(),
    }
}

async fn assert_never_dialed(listener: &TcpListener) {
    let accepted = tokio::time::timeout(Duration::from_millis(250), listener.accept()).await;
    assert!(
        accepted.is_err(),
        "the refused endpoint received a connection"
    );
}

async fn loopback_listener() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").await.unwrap()
}

#[tokio::test]
async fn an_unspecified_address_that_reaches_this_host_is_refused() {
    let listener = loopback_listener().await;
    let port = listener.local_addr().unwrap().port();

    let error = refusal(format!("http://0.0.0.0:{port}")).await;

    assert_eq!(error.to_string(), REFUSED);
    assert_never_dialed(&listener).await;
}

#[tokio::test]
async fn a_mapped_loopback_address_is_not_a_loopback_host() {
    let listener = loopback_listener().await;
    let port = listener.local_addr().unwrap().port();

    let error = refusal(format!("https://[::ffff:127.0.0.1]:{port}")).await;

    assert_eq!(error.to_string(), REFUSED);
    assert_never_dialed(&listener).await;
}

#[tokio::test]
async fn the_metadata_address_is_refused() {
    let error = refusal("https://169.254.169.254".to_string()).await;

    assert_eq!(error.to_string(), REFUSED);
}

#[tokio::test]
async fn a_private_address_is_refused() {
    let error = refusal("https://10.255.255.1".to_string()).await;

    assert_eq!(error.to_string(), REFUSED);
}

#[tokio::test]
async fn plaintext_to_a_remote_host_is_refused_without_credentials() {
    let error = refusal("http://provider.invalid".to_string()).await;

    assert_eq!(error.to_string(), REFUSED);
}

#[tokio::test]
async fn a_provider_redirect_is_refused_and_never_followed() {
    let provider = loopback_listener().await;
    let provider_address = provider.local_addr().unwrap();
    let target = loopback_listener().await;
    let target_address = target.local_addr().unwrap();
    let location = format!("http://{target_address}/v1/chat");
    let redirecting_provider = tokio::spawn(async move {
        let (mut stream, _) = provider.accept().await.unwrap();
        let mut request = [0_u8; 16 * 1024];
        let _ = stream.read(&mut request).await;
        let response = format!(
            "HTTP/1.1 307 Temporary Redirect\r\nlocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
        );
        let _ = stream.write_all(response.as_bytes()).await;
    });

    let error = refusal(format!("http://{provider_address}")).await;

    assert_eq!(error.to_string(), REFUSED);
    assert_never_dialed(&target).await;
    redirecting_provider.abort();
}

async fn serve_once(listener: TcpListener, head: &'static str, body: Vec<u8>) {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut request = [0_u8; 16 * 1024];
    let _ = stream.read(&mut request).await;
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(&body).await;
}

#[tokio::test]
async fn a_long_event_stream_is_not_cut_off_by_the_document_limit() {
    let listener = loopback_listener().await;
    let address = listener.local_addr().unwrap();
    let event = b"data: {\"type\":\"delta\",\"text\":\"chunk\"}\n\n";
    let body = event.repeat(64);
    let expected = body.clone();
    let server = tokio::spawn(serve_once(
        listener,
        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n",
        body,
    ));
    let transport = HttpTransport::new(
        HttpTransportConfig::new(format!("http://{address}")).with_max_response_bytes(256),
    )
    .unwrap();

    let streamed = transport.post_sse("/v1/chat", b"{}").await.unwrap();

    assert_eq!(streamed, expected);
    server.await.unwrap();
}

#[tokio::test]
async fn one_oversized_event_is_cut_off_while_reading() {
    let listener = loopback_listener().await;
    let address = listener.local_addr().unwrap();
    let mut body = b"data: {}\n\n".to_vec();
    body.extend(std::iter::repeat_n(b'x', 512));
    let server = tokio::spawn(serve_once(
        listener,
        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n",
        body,
    ));
    let transport = HttpTransport::new(
        HttpTransportConfig::new(format!("http://{address}")).with_max_response_bytes(256),
    )
    .unwrap();

    let error = transport.post_sse("/v1/chat", b"{}").await.unwrap_err();

    assert!(
        matches!(error, HttpTransportError::ResponseTooLarge { maximum: 256 }),
        "{error}"
    );
    server.await.unwrap();
}

#[tokio::test]
async fn a_long_line_stream_is_not_cut_off_by_the_document_limit() {
    let listener = loopback_listener().await;
    let address = listener.local_addr().unwrap();
    let body = b"{\"message\":{\"content\":\"chunk\"}}\n".repeat(64);
    let expected = body.clone();
    let server = tokio::spawn(serve_once(
        listener,
        "HTTP/1.1 200 OK\r\ncontent-type: application/x-ndjson\r\nconnection: close\r\n\r\n",
        body,
    ));
    let transport = HttpTransport::new(
        HttpTransportConfig::new(format!("http://{address}")).with_max_response_bytes(256),
    )
    .unwrap();

    let streamed = transport.post_ndjson("/api/chat", b"{}").await.unwrap();

    assert_eq!(streamed, expected);
    server.await.unwrap();
}
