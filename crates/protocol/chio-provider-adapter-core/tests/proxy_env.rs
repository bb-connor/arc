#![allow(clippy::unwrap_used)]

use std::time::Duration;

use chio_provider_adapter_core::http::{HttpTransport, HttpTransportConfig, ProviderHttpTransport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn a_proxy_named_in_the_environment_is_never_used() {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_url = format!("http://{}", proxy.local_addr().unwrap());
    let provider_address = provider.local_addr().unwrap();
    for name in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        std::env::set_var(name, &proxy_url);
    }
    for name in ["NO_PROXY", "no_proxy"] {
        std::env::remove_var(name);
    }
    let answering_provider = tokio::spawn(async move {
        let (mut stream, _) = provider.accept().await.unwrap();
        let mut request = [0_u8; 16 * 1024];
        let _ = stream.read(&mut request).await;
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}")
            .await;
    });
    let transport = HttpTransport::new(
        HttpTransportConfig::new(format!("http://{provider_address}"))
            .with_timeout(Duration::from_millis(500)),
    )
    .unwrap();

    let response = transport.post_json("/v1/chat", b"{}").await;

    let proxied = tokio::time::timeout(Duration::from_millis(250), proxy.accept()).await;
    assert!(
        proxied.is_err(),
        "the request went through the environment proxy"
    );
    assert_eq!(response.unwrap().body, b"{}");
    answering_provider.await.unwrap();
}
