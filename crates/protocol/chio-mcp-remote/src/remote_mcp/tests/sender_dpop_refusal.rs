use super::*;
use chio_core::crypto::Keypair;
use std::error::Error;

const UNAVAILABLE: &str = "urn:chio:error:transport:dpop-sender-proof-unavailable";

fn weak_sender_key() -> PublicKey {
    let mut identity = [0_u8; 32];
    identity[0] = 1;
    PublicKey::from_bytes(&identity).expect("encoded Ed25519 identity point")
}

fn dpop_header(value: &'static [u8]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        DPOP_HEADER,
        HeaderValue::from_bytes(value).expect("test header bytes"),
    );
    headers
}

fn assert_unavailable(error: SenderConstraintError) {
    assert!(matches!(error, SenderConstraintError::DpopUnavailable));
    assert_eq!(error.to_string(), UNAVAILABLE);
}

#[test]
fn sender_confirmation_rejects_weak_key_decoding() {
    let claims = serde_json::json!({"chioSenderKey": weak_sender_key().to_hex()});
    assert!(serde_json::from_value::<ChioSenderConstraintClaims>(claims).is_err());
}

#[tokio::test]
async fn sender_dpop_public_key_token_request_is_refused() {
    for key in [
        Keypair::generate().public_key().to_hex(),
        weak_sender_key().to_hex(),
    ] {
        let response = build_request_sender_constraint(Some(&key), None, None, None)
            .expect_err("a Chio DPoP sender binding cannot be issued");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let cause = response
            .extensions()
            .get::<Arc<SenderConstraintError>>()
            .expect("typed sender refusal");
        assert_eq!(cause.to_string(), UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("read refusal body");
        let value: serde_json::Value = serde_json::from_slice(&body).expect("JSON refusal body");
        assert_eq!(value["error"], "invalid_request");
        assert!(!String::from_utf8_lossy(&body).contains(&key));
    }
}

#[test]
fn dpop_bound_confirmation_is_refused_with_or_without_a_proof() {
    let claims = ChioSenderConstraintClaims {
        chio_sender_key: Some(Keypair::generate().public_key().to_hex()),
        ..Default::default()
    };
    for headers in [HeaderMap::new(), dpop_header(b"presented-proof")] {
        assert_unavailable(
            sender_constraint::validate_sender_constraint(Some(&claims), &headers)
                .expect_err("a DPoP-bound confirmation never degrades to a bearer"),
        );
    }
}

#[test]
fn presented_dpop_proof_is_refused_for_every_confirmation() {
    let mtls = ChioSenderConstraintClaims {
        mtls_thumbprint_sha256: Some("thumbprint".into()),
        ..Default::default()
    };
    for claims in [None, Some(&mtls)] {
        for headers in [
            dpop_header(b"presented-proof"),
            dpop_header(b"private-marker\xff"),
        ] {
            assert_unavailable(
                sender_constraint::validate_sender_constraint(claims, &headers)
                    .expect_err("a presented DPoP proof is refused"),
            );
        }
    }
}

#[test]
fn sender_headers_cannot_claim_transport_bindings() {
    for (header, claims) in [
        (
            CHIO_MTLS_THUMBPRINT_HEADER,
            ChioSenderConstraintClaims {
                mtls_thumbprint_sha256: Some("thumbprint".into()),
                ..Default::default()
            },
        ),
        (
            CHIO_RUNTIME_ATTESTATION_HEADER,
            ChioSenderConstraintClaims {
                chio_attestation_sha256: Some("attestation".into()),
                ..Default::default()
            },
        ),
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(
            header,
            HeaderValue::from_bytes(b"private-marker\xff").expect("test header bytes"),
        );
        let error = sender_constraint::validate_sender_constraint(Some(&claims), &headers)
            .expect_err("caller headers are not transport identity");
        assert!(matches!(
            error,
            SenderConstraintError::MtlsBinding | SenderConstraintError::UnsupportedSchema
        ));
        assert!(error.source().is_none());
        assert!(!format!("{error:?} {error}").contains("private-marker"));
    }
}

#[tokio::test]
async fn sender_key_rejection_keeps_decode_source_out_of_the_wire_response() {
    let response = build_request_sender_constraint(Some("private-invalid-key"), None, None, None)
        .expect_err("an undecodable sender key is refused");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .expect("read refusal body");
    let value: serde_json::Value = serde_json::from_slice(&body).expect("JSON refusal body");
    assert_eq!(value["error"], "invalid_request");
    assert!(!String::from_utf8_lossy(&body).contains("private-invalid-key"));
}
