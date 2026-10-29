use super::common::{
    client_directory, key, relay_client, sample_batch, PeerDirectory, PheromoneRelayError,
    RelayProfile, NOW, PHEROMONE_BATCH_RELAY_PATH,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn post_to(endpoint: String, profile: RelayProfile) -> PheromoneRelayError {
    let directory = PeerDirectory::from_document(client_directory(&key(2), endpoint), NOW).unwrap();
    relay_client(directory, key(1), profile)
        .post_batch(
            "did:chio:llamaworks",
            "did:chio:buyer-kernel",
            &sample_batch(),
            "relay-nonce-egress",
        )
        .await
        .unwrap_err()
}

async fn assert_never_dialed(listener: &TcpListener) {
    let accepted = tokio::time::timeout(Duration::from_millis(250), listener.accept()).await;
    assert!(accepted.is_err(), "the peer listener received a connection");
}

async fn loopback_listener() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").await.unwrap()
}

#[tokio::test]
async fn a_production_relay_refuses_a_plain_http_peer() {
    let listener = loopback_listener().await;
    let address = listener.local_addr().unwrap();

    let error = post_to(format!("http://{address}"), RelayProfile::Production).await;

    assert_eq!(error.code(), "endpoint_denied", "{error}");
    assert_never_dialed(&listener).await;
}

#[tokio::test]
async fn a_production_relay_refuses_a_loopback_https_peer() {
    let listener = loopback_listener().await;
    let address = listener.local_addr().unwrap();

    let error = post_to(format!("https://{address}"), RelayProfile::Production).await;

    assert_eq!(error.code(), "endpoint_denied", "{error}");
    assert_never_dialed(&listener).await;
}

#[tokio::test]
async fn a_production_relay_refuses_localhost_by_name() {
    let listener = loopback_listener().await;
    let port = listener.local_addr().unwrap().port();

    let error = post_to(
        format!("https://localhost:{port}"),
        RelayProfile::Production,
    )
    .await;

    assert_eq!(error.code(), "endpoint_denied", "{error}");
    assert_never_dialed(&listener).await;
}

#[tokio::test]
async fn a_production_relay_refuses_the_metadata_address() {
    let error = post_to(
        "https://169.254.169.254".to_string(),
        RelayProfile::Production,
    )
    .await;

    assert_eq!(error.code(), "endpoint_denied", "{error}");
}

#[tokio::test]
async fn a_local_dev_relay_refuses_plain_http_to_a_non_loopback_peer() {
    let error = post_to(
        "http://peer.invalid:8080".to_string(),
        RelayProfile::LocalDev,
    )
    .await;

    assert_eq!(error.code(), "endpoint_denied", "{error}");
}

#[tokio::test]
async fn a_local_dev_relay_does_not_follow_a_peer_redirect() {
    let peer = loopback_listener().await;
    let peer_address = peer.local_addr().unwrap();
    let target = loopback_listener().await;
    let target_address = target.local_addr().unwrap();
    let location = format!("http://{target_address}{PHEROMONE_BATCH_RELAY_PATH}");
    let redirecting_peer = tokio::spawn(async move {
        let (mut stream, _) = peer.accept().await.unwrap();
        let mut request = [0_u8; 16 * 1024];
        let _ = stream.read(&mut request).await;
        let response = format!(
            "HTTP/1.1 302 Found\r\nlocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
        );
        let _ = stream.write_all(response.as_bytes()).await;
    });

    let error = post_to(format!("http://{peer_address}"), RelayProfile::LocalDev).await;

    assert_eq!(error.code(), "endpoint_denied", "{error}");
    assert_never_dialed(&target).await;
    redirecting_peer.abort();
}
