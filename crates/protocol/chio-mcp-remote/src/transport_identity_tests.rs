use super::*;
use crate::*;
use axum::{body::Body, http::HeaderValue, routing::post, Router};
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const SECRET: &[u8] = b"independent-proxy-credential-32-bytes";
fn jwt(key: &Keypair, claims: Value) -> Result<String, serde_json::Error> {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
    let input = format!("{header}.{payload}");
    let signature = URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).to_bytes());
    Ok(format!("{input}.{signature}"))
}
fn verifier(key: &Keypair) -> Result<JwtBearerVerifier, chio_kernel::dpop::DpopError> {
    Ok(JwtBearerVerifier {
        clock: RemoteClock::default(),
        key_source: JwtVerificationKeySource::Static(key.public_key()),
        issuer: Some("https://issuer.example".into()),
        audience: Some("chio-mcp".into()),
        required_scopes: vec![],
        provider_profile: JwtProviderProfile::Generic,
        enterprise_provider_registry: None,
        sender_dpop_nonce_store: Arc::new(DpopNonceStore::new(32, Duration::from_secs(300))?),
        sender_dpop_config: DpopConfig::default(),
    })
}

#[tokio::test]
async fn inbound_authority_proxy_authentication_controls_jwt_identity() -> TestResult {
    let key = Keypair::generate();
    let verifier = Arc::new(verifier(&key)?);
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let token = jwt(
        &key,
        json!({"iss":"https://issuer.example","aud":"chio-mcp","sub":"sender",
        "exp":RemoteClock::default().seconds()?+300,"cnf":{"x5t#S256":"trusted-thumbprint"}}),
    )?;
    let app = Router::new()
        .route(
            "/mcp",
            post(move |request: Request| {
                let verifier = verifier.clone();
                let calls = counted.clone();
                let token = token.clone();
                async move {
                    // Authentication sees no caller identity or proxy credential headers.
                    assert!(!request.headers().contains_key(PROXY_AUTH));
                    assert!(!request.headers().contains_key(CHIO_MTLS_THUMBPRINT_HEADER));
                    match verifier.authenticate_token(
                        &token,
                        SenderRequest::from_request(&request),
                        None,
                        None,
                        "POST",
                        "chio-mcp",
                    ) {
                        Ok(_) => {
                            calls.fetch_add(1, Ordering::SeqCst);
                            StatusCode::OK.into_response()
                        }
                        Err(response) => response,
                    }
                }
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            Some(TrustedProxyConfig::new(
                vec!["127.0.0.1".parse()?],
                Zeroizing::new(SECRET.to_vec()),
            )?),
            authenticate_proxy,
        ));
    for (peer, credential, thumbprint, expected) in [
        (
            Some("127.0.0.1:1000"),
            Some(SECRET),
            Some("trusted-thumbprint"),
            StatusCode::OK,
        ),
        (
            Some("127.0.0.1:1000"),
            None,
            Some("trusted-thumbprint"),
            StatusCode::UNAUTHORIZED,
        ),
        (
            Some("127.0.0.1:1000"),
            Some(b"wrong".as_slice()),
            Some("trusted-thumbprint"),
            StatusCode::UNAUTHORIZED,
        ),
        (
            Some("192.0.2.1:1000"),
            Some(SECRET),
            Some("trusted-thumbprint"),
            StatusCode::UNAUTHORIZED,
        ),
        (
            None,
            Some(SECRET),
            Some("trusted-thumbprint"),
            StatusCode::UNAUTHORIZED,
        ),
        (
            Some("127.0.0.1:1000"),
            Some(SECRET),
            Some("wrong-thumbprint"),
            StatusCode::UNAUTHORIZED,
        ),
        (Some("127.0.0.1:1000"), None, None, StatusCode::UNAUTHORIZED),
    ] {
        let mut request = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("x-forwarded-for", "127.0.0.1")
            .body(Body::empty())?;
        if let Some(peer) = peer {
            request
                .extensions_mut()
                .insert(ConnectInfo(chio_http_serve::CappedPeerAddr(peer.parse()?)));
        }
        if let Some(secret) = credential {
            request
                .headers_mut()
                .insert(PROXY_AUTH, HeaderValue::from_bytes(secret)?);
        }
        if let Some(value) = thumbprint {
            request
                .headers_mut()
                .insert(CHIO_MTLS_THUMBPRINT_HEADER, HeaderValue::from_str(value)?);
        }
        assert_eq!(app.clone().oneshot(request).await?.status(), expected);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn inbound_authority_proxy_rejects_ambiguous_headers_with_typed_causes() -> TestResult {
    use std::error::Error;
    let proxy =
        TrustedProxyConfig::new(vec!["127.0.0.1".parse()?], Zeroizing::new(SECRET.to_vec()))?;
    let mut request = Request::builder()
        .header(PROXY_AUTH, HeaderValue::from_bytes(SECRET)?)
        .body(Body::empty())?;
    request
        .extensions_mut()
        .insert(ConnectInfo(chio_http_serve::CappedPeerAddr(
            "127.0.0.1:1".parse()?,
        )));
    request.headers_mut().insert(
        CHIO_RUNTIME_ATTESTATION_HEADER,
        HeaderValue::from_bytes(b"private-marker\xff")?,
    );
    let error = match proxy.authenticate(&request) {
        Ok(_) => return Err("non-text identity admitted".into()),
        Err(error) => error,
    };
    assert!(error
        .source()
        .is_some_and(|cause| cause.is::<axum::http::header::ToStrError>()));
    assert!(!error.to_string().contains("private-marker"));
    request
        .headers_mut()
        .remove(CHIO_RUNTIME_ATTESTATION_HEADER);
    request
        .headers_mut()
        .append(PROXY_AUTH, HeaderValue::from_bytes(SECRET)?);
    assert!(proxy.authenticate(&request).is_err());
    assert!(!format!("{proxy:?}").contains(std::str::from_utf8(SECRET)?));
    Ok(())
}

#[test]
fn inbound_authority_introspection_confirmation_is_closed() -> TestResult {
    for cnf in [
        json!({"jkt":"unsupported"}),
        json!({}),
        Value::Null,
        json!({"x5t#S256":null}),
        json!({"chioAttestationSha256":"unbound"}),
    ] {
        let body = serde_json::to_vec(&json!({"active":true,"cnf":cnf}))?;
        assert!(decode_json::<OAuthIntrospectionResponse>(&body, MAX_AUTH_JSON_BYTES).is_err());
    }
    let valid = br#"{"active":true,"cnf":{"x5t#S256":"trusted-thumbprint"}}"#;
    assert!(decode_json::<OAuthIntrospectionResponse>(valid, MAX_AUTH_JSON_BYTES).is_ok());
    Ok(())
}
