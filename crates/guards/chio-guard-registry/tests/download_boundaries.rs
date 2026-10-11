//! The production OCI reader must bound the actual HTTP body before retaining it.
use std::collections::BTreeMap;
use std::sync::Arc;

use chio_guard_registry::{
    GuardArtifactConfig, GuardOciRef, GuardPublishArtifact, GuardPublishArtifactInput,
    GuardRegistryClient, GuardRegistryConfig, GuardRegistryError, RegistryCredentials,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Registry {
    authority: String,
    server: JoinHandle<()>,
}

impl Registry {
    async fn start(routes: BTreeMap<String, Vec<u8>>) -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let authority = listener.local_addr()?.to_string();
        let routes = Arc::new(routes);
        let server = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let routes = Arc::clone(&routes);
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buffer = [0; 1024];
                    while request.len() < 32 * 1024
                        && !request.windows(4).any(|bytes| bytes == b"\r\n\r\n")
                    {
                        match stream.read(&mut buffer).await {
                            Ok(0) | Err(_) => return,
                            Ok(len) => request.extend_from_slice(&buffer[..len]),
                        }
                    }
                    let request = String::from_utf8_lossy(&request);
                    let path = request.split_whitespace().nth(1).unwrap_or("");
                    if let Some(response) = routes.get(path) {
                        let _ = stream.write_all(response).await;
                    } else {
                        let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                    }
                });
            }
        });
        Ok(Self { authority, server })
    }

    async fn pull(
        &self,
        digest: &str,
    ) -> Result<chio_guard_registry::PulledGuardArtifact, GuardRegistryError> {
        let client = GuardRegistryClient::try_new(GuardRegistryConfig {
            allow_http_registries: vec![self.authority.clone()],
            ..Default::default()
        })?;
        let reference: GuardOciRef =
            format!("oci://{}/guards/test@{digest}", self.authority).parse()?;
        client
            .pull_guard_artifact(&reference, &RegistryCredentials::Anonymous)
            .await
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn manifest_path(digest: &str) -> String {
    format!("/v2/guards/test/manifests/{digest}")
}
fn blob_path(digest: &str) -> String {
    format!("/v2/guards/test/blobs/{digest}")
}
fn response(bytes: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    )
    .into_bytes();
    response.extend_from_slice(bytes);
    response
}
fn artifact() -> Result<GuardPublishArtifact, GuardRegistryError> {
    GuardPublishArtifact::build(GuardPublishArtifactInput {
        wit: b"wit".to_vec(),
        module: b"wasm".to_vec(),
        manifest: b"{}".to_vec(),
        config: GuardArtifactConfig::new("ed25519:fixture", 1, 65536, "fixture"),
        signer_subject: None,
    })
}
fn routes(artifact: &GuardPublishArtifact) -> TestResult<(String, BTreeMap<String, Vec<u8>>)> {
    let manifest = serde_json::to_vec(&artifact.manifest)?;
    let hash = digest(&manifest);
    let mut routes = BTreeMap::from([
        (manifest_path(&hash), response(&manifest)),
        (
            blob_path(&artifact.manifest.config.digest),
            response(&artifact.config.data),
        ),
    ]);
    for layer in &artifact.layers {
        routes.insert(blob_path(&digest(&layer.data)), response(&layer.data));
    }
    Ok((hash, routes))
}

#[tokio::test]
async fn downloads_digest_pinned_artifact_through_bounded_transport() -> TestResult {
    let artifact = artifact()?;
    let (hash, routes) = routes(&artifact)?;
    let registry = Registry::start(routes).await?;
    let pulled = registry.pull(&hash).await?;
    assert_eq!(pulled.module.data, b"wasm");
    assert_eq!(pulled.wit.data, b"wit");
    assert_eq!(pulled.manifest.data, b"{}");
    Ok(())
}

#[tokio::test]
async fn rejects_manifest_content_length_before_body_retention() -> TestResult {
    let hash = digest(b"oversized");
    let routes = BTreeMap::from([(
        manifest_path(&hash),
        b"HTTP/1.1 200 OK\r\nContent-Length: 16777217\r\nConnection: close\r\n\r\n".to_vec(),
    )]);
    let registry = Registry::start(routes).await?;
    assert!(matches!(
        registry.pull(&hash).await,
        Err(GuardRegistryError::ReferrersEgress { .. })
    ));
    Ok(())
}

#[tokio::test]
async fn rejects_streaming_blob_over_descriptor_size_without_content_length() -> TestResult {
    let artifact = artifact()?;
    let (hash, mut routes) = routes(&artifact)?;
    // Descriptor permits 3 bytes. A chunked 4-byte body must fail in transport,
    // before the descriptor's post-download size and digest checks.
    routes.insert(blob_path(&artifact.manifest.layers[0].digest),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nwi\r\n2\r\nt!\r\n0\r\n\r\n".to_vec());
    let registry = Registry::start(routes).await?;
    assert!(matches!(
        registry.pull(&hash).await,
        Err(GuardRegistryError::ReferrersEgress { .. })
    ));
    Ok(())
}

#[tokio::test]
async fn rejects_original_manifest_duplicates_even_when_digest_matches() -> TestResult {
    let body = br#"{"unknown":{"private-marker":1,"private-marker":2}}"#;
    let hash = digest(body);
    let registry =
        Registry::start(BTreeMap::from([(manifest_path(&hash), response(body))])).await?;
    match registry.pull(&hash).await {
        Err(GuardRegistryError::Input(error)) => {
            assert!(!format!("{error:?} {error}").contains("private-marker"));
            assert!(std::error::Error::source(&error).is_some());
        }
        other => panic!("duplicate manifest unexpectedly accepted or wrong failure: {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn rejects_oversized_descriptor_before_fetching_blobs() -> TestResult {
    let mut artifact = artifact()?;
    artifact.manifest.layers[0].size = 64 * 1024 * 1024 + 1;
    let bytes = serde_json::to_vec(&artifact.manifest)?;
    let hash = digest(&bytes);
    let registry =
        Registry::start(BTreeMap::from([(manifest_path(&hash), response(&bytes))])).await?;
    assert!(matches!(
        registry.pull(&hash).await,
        Err(GuardRegistryError::InvalidClientConfig(
            "guard artifact exceeds aggregate byte limit"
        ))
    ));
    Ok(())
}
