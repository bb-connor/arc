#![allow(clippy::unwrap_used)]
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn response_bound_checks_content_length_and_chunked_actual_bytes() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("12345"))
        .mount(&server)
        .await;
    let transport =
        HttpTransport::new(HttpTransportConfig::new(server.uri()).with_max_response_bytes(4))
            .unwrap();
    assert!(matches!(
        transport.post_json("/", b"{}").await,
        Err(HttpTransportError::ResponseTooLarge { maximum: 4 })
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        socket.read(&mut request).await.unwrap();
        socket.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n").await.unwrap();
    });
    let transport = HttpTransport::new(
        HttpTransportConfig::new(format!("http://{address}")).with_max_response_bytes(4),
    )
    .unwrap();
    assert!(matches!(
        transport.post_json("/", b"{}").await,
        Err(HttpTransportError::ResponseTooLarge { maximum: 4 })
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn redirects_are_denied_and_failure_body_is_not_retained() {
    let origin = MockServer::start().await;
    let target = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("location", target.uri())
                .set_body_string("private-provider-payload"),
        )
        .mount(&origin)
        .await;
    let config =
        HttpTransportConfig::new(origin.uri()).with_auth(AuthScheme::Bearer("secret-key".into()));
    assert!(!format!("{config:?}").contains("secret-key"));
    let transport = HttpTransport::new(config).unwrap();
    let error = transport.post_json("/", b"{}").await.unwrap_err();
    assert!(matches!(error, HttpTransportError::Status { code: 307 }));
    assert!(!format!("{error:?} {error}").contains("private-provider-payload"));
    assert!(target.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn native_transport_cause_survives_without_query_credentials() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let transport = HttpTransport::new(
        HttpTransportConfig::new(format!("http://{address}")).with_auth(AuthScheme::QueryParam {
            name: "key".into(),
            value: "private-query-secret".into(),
        }),
    )
    .unwrap();
    let native = transport.post_json("/", b"{}").await.unwrap_err();
    let error = map_transport_error("test", native);
    assert!(!format!("{error:?} {error}").contains("private-query-secret"));
    let mut source = std::error::Error::source(&error);
    let mut found_reqwest = false;
    while let Some(cause) = source {
        assert!(!cause.to_string().contains("private-query-secret"));
        found_reqwest |= cause.downcast_ref::<reqwest::Error>().is_some();
        source = cause.source();
    }
    assert!(found_reqwest);
}

#[test]
fn malformed_headers_and_urls_retain_native_parser_causes() {
    for config in [
        HttpTransportConfig::new("https://example.com").with_header("bad header", "x"),
        HttpTransportConfig::new("https://example.com").with_header("valid", "bad\nvalue"),
        HttpTransportConfig::new("http://["),
    ] {
        let error = match HttpTransport::new(config) {
            Err(error) => error,
            Ok(_) => panic!("invalid transport config accepted"),
        };
        assert!(std::error::Error::source(&error).is_some());
        assert_eq!(
            error.to_string(),
            "urn:chio:error:transport:invalid-request-shape"
        );
    }
}
