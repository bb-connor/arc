use base64::{engine::general_purpose::STANDARD, Engine};
use sigstore_rekor::{HashedRekordV2, RekorClient, RekorEntryBody};
use sigstore_types::{DerCertificate, Sha256Hash, SignatureBytes};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn body_parser_rejects_bad_encoding_and_unsupported_dispatch() {
    for encoded in [
        "%%%".to_owned(),
        STANDARD.encode([0xff]),
        STANDARD.encode("{"),
        STANDARD.encode("{}"),
    ] {
        assert!(RekorEntryBody::from_base64_json(&encoded, "hashedrekord", "0.0.1").is_err());
    }
    assert!(RekorEntryBody::from_base64_json(&STANDARD.encode("{}"), "unknown", "0.0.1").is_err());
    assert!(RekorEntryBody::from_base64_json(&STANDARD.encode("{}"), "dsse", "999").is_err());
}

#[test]
fn certificate_extraction_rejects_invalid_pem_and_utf8() {
    use sigstore_rekor::body::PublicKeyContent;
    use sigstore_types::PemContent;
    for bytes in [vec![0xff], b"not PEM".to_vec()] {
        assert!(PublicKeyContent {
            content: PemContent::new(bytes)
        }
        .to_certificate()
        .is_err());
    }
}

async fn reply_once(status: &str, body: &str) -> (String, tokio::task::JoinHandle<String>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let response = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    let handle = tokio::spawn(async move {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let count = stream.read(&mut chunk).await.unwrap();
                assert_ne!(count, 0);
                request.extend_from_slice(&chunk[..count]);
                if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..end]);
                    let size = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if request.len() >= end + 4 + size {
                        break;
                    }
                }
            }
            stream.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8(request).unwrap()
        })
        .await
        .unwrap()
    });
    (format!("http://{address}"), handle)
}

#[tokio::test]
async fn retrieval_propagates_transport_and_shape_errors() {
    for (status, body) in [("503 Unavailable", "{}"), ("200 OK", "{}"), ("200 OK", "{")] {
        let (url, server) = reply_once(status, body).await;
        let result = RekorClient::new(url).get_entry_by_uuid("requested").await;
        assert!(result.is_err());
        assert!(server
            .await
            .unwrap()
            .starts_with("GET /api/v1/log/entries/requested HTTP/1.1"));
    }
}

#[tokio::test]
async fn retrieval_is_untrusted_transport_not_request_identity_verification() {
    let response = r#"{"different":{"body":"e30=","integratedTime":0,"logID":"00","logIndex":7}}"#;
    let (url, server) = reply_once("200 OK", response).await;
    let entry = RekorClient::new(url)
        .get_entry_by_uuid("requested")
        .await
        .unwrap();
    assert_eq!(entry.uuid.as_str(), "different");
    assert!(entry.verification.is_none());
    server.await.unwrap();
}

#[tokio::test]
async fn v2_numeric_fallback_is_not_authenticated_time_or_position() {
    let response = r#"{"logIndex":"invalid","logId":{"keyId":"AA=="},"kindVersion":{"kind":"hashedrekord","version":"0.0.2"},"integratedTime":"invalid","canonicalizedBody":"e30="}"#;
    let (url, server) = reply_once("200 OK", response).await;
    let proposed = HashedRekordV2::new(
        &Sha256Hash::from_bytes([1; 32]),
        &SignatureBytes::from_bytes(b"signature"),
        &DerCertificate::new(vec![0x30, 0]),
    );
    let entry = RekorClient::new(url)
        .create_entry_v2(proposed)
        .await
        .unwrap();
    assert_eq!((entry.log_index, entry.integrated_time), (0, 0));
    let verification = entry.verification.unwrap();
    assert!(verification.inclusion_proof.is_none());
    assert!(verification.signed_entry_timestamp.is_none());
    assert!(server
        .await
        .unwrap()
        .starts_with("POST /api/v2/log/entries HTTP/1.1"));
}
