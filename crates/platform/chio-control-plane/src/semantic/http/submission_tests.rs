//! Real authenticated HTTP submission through the contract-backed dispatcher.
use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio_rustls::{rustls, TlsAcceptor};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Reply {
    Success,
    Redirect,
    ClientError,
    ServerError,
    ForeignIdentity,
    DeclaredOversize,
    ChunkedSuccess,
    ChunkedOversize,
    Timeout,
}

async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 1024];
    let mut expected = None;
    loop {
        if let Some(expected) = expected {
            if bytes.len() >= expected {
                bytes.truncate(expected);
                return Ok(bytes);
            }
        }
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            return Err("provider request ended before its complete body".into());
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.len() > MAX_RECOVERY_WIRE_BYTES + 8192 {
            return Err("provider request exceeds fixture bound".into());
        }
        if expected.is_none() {
            if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                let headers = std::str::from_utf8(&bytes[..end])?;
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then_some(value.trim())
                    })
                    .ok_or("provider request lacks a declared body length")?
                    .parse::<usize>()?;
                if length > MAX_RECOVERY_WIRE_BYTES || end > 8192 {
                    return Err("provider request header or body exceeds fixture bound".into());
                }
                expected = Some(
                    end.checked_add(4)
                        .and_then(|end| end.checked_add(length))
                        .ok_or("provider request length overflow")?,
                );
            } else if bytes.len() > 8192 {
                return Err("provider request headers exceed fixture bound".into());
            }
        }
    }
}

fn provider_response(request: &SemanticTransportRequestV1) -> SemanticProviderResponseV1 {
    SemanticProviderResponseV1 {
        provider: request.destination.provider.clone(),
        account: request.destination.account.clone(),
        resource: request.destination.resource.clone(),
        checked_provider_version: request.provider_version.clone(),
        operation: request.operation.clone(),
        attempt: request.attempt.clone(),
        payload: request.payload.clone(),
    }
}

async fn run_case(reply: Reply, kind: SemanticOperationKindV1) -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let endpoint = format!("https://{address}/issues");
    let mut request = super::tests::request().map_err(|error| error.to_string())?;
    request.kind = kind;
    request.destination.endpoint = ProtectedText::new(&endpoint)?;
    let mut contract = HttpEgressContract::permissive_for_tests(&address.to_string());
    contract.allowed_schemes = std::collections::BTreeSet::from(["https".to_owned()]);
    contract.max_redirect_chain = 0;
    contract.max_response_bytes = 512;
    let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()])?;
    let certificate = reqwest::Certificate::from_der(certified.cert.der())?;
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(
        vec![certified.cert.der().clone()],
        rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            certified.key_pair.serialize_der(),
        )),
    )?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let received = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let connections = Arc::new(AtomicUsize::new(0));
    let mut response = provider_response(&request);
    if reply == Reply::ForeignIdentity {
        response.account = ProviderAccountId::new("unselected-account")?;
    }
    if reply == Reply::ChunkedOversize {
        let mut fields = response.payload.fields.as_slice().to_vec();
        fields[0].value = SemanticValueV1::Text {
            value: ProtectedText::new(&"private-transport-canary".repeat(30))?,
        };
        response.payload.fields = NonEmptyBoundedList::new(fields)?;
    }
    let body = chio_core_types::canonical_json_bytes(&response)?;
    if reply == Reply::ChunkedOversize {
        assert!(body.len() > 512 && body.len() < MAX_RECOVERY_WIRE_BYTES);
    } else {
        assert!(body.len() < 512);
    }
    let server_received = received.clone();
    let server_release = release.clone();
    let server_connections = connections.clone();
    let mut server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await?;
        server_connections.fetch_add(1, Ordering::SeqCst);
        let mut stream = acceptor.accept(socket).await?;
        let request_bytes = read_request(&mut stream).await?;
        match reply {
            Reply::Timeout => {}
            Reply::DeclaredOversize => {
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 513\r\nContent-Type: application/json\r\n\r\n").await?;
                stream.flush().await?;
            }
            Reply::ChunkedSuccess | Reply::ChunkedOversize => {
                let sent = async {
                    stream.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n").await?;
                    for chunk in body.chunks(300) {
                        stream
                            .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                            .await?;
                        stream.write_all(chunk).await?;
                        stream.write_all(b"\r\n").await?;
                    }
                    stream.write_all(b"0\r\n\r\n").await?;
                    stream.flush().await?;
                    Ok::<_, std::io::Error>(())
                }.await;
                if let Err(error) = sent {
                    // The bounded client may close while a valid oversized
                    // response is still being sent. Small chunked JSON must
                    // remain a successful positive control.
                    if reply != Reply::ChunkedOversize {
                        return Err(error.into());
                    }
                }
            }
            _ => {
                let status = match reply {
                    Reply::Redirect => "307 Temporary Redirect",
                    Reply::ClientError => "403 Forbidden",
                    Reply::ServerError => "503 Service Unavailable",
                    _ => "200 OK",
                };
                let location = if reply == Reply::Redirect {
                    "Location: /redirected\r\n"
                } else {
                    ""
                };
                let header = format!(
                    "HTTP/1.1 {status}\r\n{location}Content-Length: {}\r\nContent-Type: application/json\r\n\r\n",
                    body.len()
                );
                stream.write_all(header.as_bytes()).await?;
                stream.write_all(&body).await?;
                stream.flush().await?;
            }
        }
        server_received.notify_one();
        // Keep the body/connection withheld until the caller has returned.
        // Prefer an already queued second connection over cleanup notification.
        loop {
            tokio::select! {
                biased;
                accepted = listener.accept() => {
                    let (_socket, _) = accepted?;
                    server_connections.fetch_add(1, Ordering::SeqCst);
                }
                () = server_release.notified() => break,
            }
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(request_bytes)
    });
    let mut transport = HttpSemanticTransport::new(
        request.destination.clone(),
        contract.clone(),
        "fixture-provider-credential".to_owned(),
        ProviderPreconditionGuaranteeV1::AtomicIfMatch,
    )?;
    transport.client = client_builder_with_contract(&contract)
        .https_only(true)
        .no_retries()
        .add_root_certificate(certificate)
        .timeout(Duration::from_secs(4))
        .connect_timeout(Duration::from_secs(2))
        .build()?;
    let transport = Arc::new(transport);
    let submission = crate::semantic::submission_for_transport_test(request.clone());
    let mut client = tokio::spawn(async move { transport.submit(submission).await });
    let observed = tokio::time::timeout(Duration::from_secs(2), received.notified()).await;
    let result = if observed.is_ok() {
        tokio::time::timeout(
            if reply == Reply::Timeout {
                Duration::from_secs(5)
            } else {
                Duration::from_secs(1)
            },
            &mut client,
        )
        .await
    } else {
        client.abort();
        tokio::time::timeout(Duration::from_secs(1), &mut client).await
    };
    if result.is_err() {
        client.abort();
        let _ = client.await;
    }
    release.notify_one();
    let request_bytes = match tokio::time::timeout(Duration::from_secs(2), &mut server).await {
        Ok(result) => result??,
        Err(error) => {
            server.abort();
            let _ = server.await;
            return Err(error.into());
        }
    };
    observed?;
    let result = result??;
    if matches!(reply, Reply::Success | Reply::ChunkedSuccess) {
        assert_eq!(result?, request.payload);
    } else {
        let error = result.err().ok_or("provider refusal returned a payload")?;
        assert!(!error.to_string().contains("private-transport-canary"));
    }
    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "one native submission cannot redirect or replay"
    );
    let headers_end = request_bytes
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .ok_or("provider headers absent")?
        + 4;
    let request_line = std::str::from_utf8(&request_bytes[..headers_end])?
        .lines()
        .next()
        .ok_or("provider request line absent")?;
    assert_eq!(
        request_line,
        if kind == SemanticOperationKindV1::SupportRead {
            "GET /issues HTTP/1.1"
        } else {
            "POST /issues HTTP/1.1"
        }
    );
    let actual: SemanticProviderRequestV1 = decode_contract(&request_bytes[headers_end..])?;
    assert_eq!(actual.account, request.destination.account);
    assert_eq!(actual.resource, request.destination.resource);
    assert_eq!(actual.operation, request.operation);
    assert_eq!(actual.attempt, request.attempt);
    Ok(())
}

#[tokio::test]
async fn semantic_http_submit_accepts_only_bound_successful_identity() -> TestResult {
    for kind in [
        SemanticOperationKindV1::IssueWrite,
        SemanticOperationKindV1::SupportRead,
    ] {
        run_case(Reply::Success, kind).await?;
        run_case(Reply::ForeignIdentity, kind).await?;
    }
    Ok(())
}

#[tokio::test]
async fn semantic_http_submit_refuses_redirect_and_error_status_without_replay() -> TestResult {
    for reply in [Reply::Redirect, Reply::ClientError, Reply::ServerError] {
        run_case(reply, SemanticOperationKindV1::IssueWrite).await?;
    }
    Ok(())
}

#[tokio::test]
async fn semantic_http_submit_enforces_declared_and_chunked_response_bounds() -> TestResult {
    run_case(Reply::ChunkedSuccess, SemanticOperationKindV1::IssueWrite).await?;
    run_case(Reply::DeclaredOversize, SemanticOperationKindV1::IssueWrite).await?;
    run_case(Reply::ChunkedOversize, SemanticOperationKindV1::IssueWrite).await
}

#[tokio::test]
async fn semantic_http_submit_deadline_refuses_a_provider_that_withholds_response() -> TestResult {
    run_case(Reply::Timeout, SemanticOperationKindV1::IssueWrite).await
}
