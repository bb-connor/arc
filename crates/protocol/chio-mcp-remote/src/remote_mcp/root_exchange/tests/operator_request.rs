//! Signed operator root requests: the signer, the strict decoder, and the
//! verifier under the pinned operator key.

use super::*;
use crate::root_exchange::kinds::operator_key::{
    self, OperatorRootRequest, SignedOperatorRootRequest, CHIO_OPERATOR_ROOT_REQUEST_SCHEMA,
    MAX_OPERATOR_ROOT_REQUEST_BYTES, OPERATOR_KEY_ISSUER,
};
use chio_core::crypto::{sign_wrapped, verify_wrapped, Ed25519Backend, Signature};
use chio_core::root_authority::Sha256Digest;

const REVOCATION_REQUEST_SCHEMA: &str = "chio.revocation-request.v1";

fn operator() -> Ed25519Backend {
    Ed25519Backend::new(Keypair::from_seed(&[0x21; 32]))
}

fn other_operator() -> Ed25519Backend {
    Ed25519Backend::new(Keypair::from_seed(&[0x22; 32]))
}

fn pinned_key() -> PublicKey {
    operator().keypair().public_key()
}

fn request_value(edit: impl FnOnce(&mut Value)) -> Value {
    let mut request = json!({
        "request_id": "req-1",
        "principal": "ops:carol",
        "tenant_value": "acme",
        "scope": { "grants": [grant("search")] },
        "holder": "edge_session",
        "expires_at": NOW + 120
    });
    edit(&mut request);
    request
}

fn request(edit: impl FnOnce(&mut Value)) -> OperatorRootRequest {
    OperatorRootRequest::parse(&serde_json::to_vec(&request_value(edit)).unwrap()).unwrap()
}

fn signed_wire(backend: &Ed25519Backend) -> Value {
    let signed = SignedOperatorRootRequest::sign(request(|_| {}), backend).unwrap();
    serde_json::from_slice(&signed.to_canonical_json().unwrap()).unwrap()
}

fn signing_body(wire: &Value) -> Value {
    let mut body = wire.clone();
    body.as_object_mut().unwrap().remove("signature");
    body
}

fn parse_value(wire: &Value) -> Result<SignedOperatorRootRequest, RootExchangeError> {
    SignedOperatorRootRequest::parse(&serde_json::to_vec(wire).unwrap())
}

#[test]
fn operator_request_signed_by_pinned_key_verifies() {
    let signed = SignedOperatorRootRequest::sign(request(|_| {}), &operator()).unwrap();
    let bytes = signed.to_canonical_json().unwrap();
    let wire: Value = serde_json::from_slice(&bytes).unwrap();
    let members: Vec<&str> = wire
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        members,
        [
            "expires_at",
            "holder",
            "principal",
            "request_id",
            "schema",
            "scope",
            "signature",
            "tenant_value"
        ]
    );
    assert_eq!(wire["schema"], json!(CHIO_OPERATOR_ROOT_REQUEST_SCHEMA));

    let body = signing_body(&wire);
    let signature = Signature::from_hex(wire["signature"].as_str().unwrap()).unwrap();
    verify_wrapped(
        &pinned_key(),
        CHIO_OPERATOR_ROOT_REQUEST_SCHEMA,
        &body,
        &signature,
    )
    .unwrap();

    let parsed = SignedOperatorRootRequest::parse(&bytes).unwrap();
    assert_eq!(parsed.to_canonical_json().unwrap(), bytes);
    let verified = parsed.verify(&pinned_key()).unwrap();
    assert_eq!(
        verified.request_digest(),
        Sha256Digest::from_hash(sha256(&canonical_json_bytes(&body).unwrap()))
    );

    let evidence = operator_key::verify(&verified, NOW).unwrap();
    assert_eq!(evidence.issuer, OPERATOR_KEY_ISSUER);
    assert_eq!(evidence.principal, "ops:carol");
    assert_eq!(evidence.tenant, "acme");
    assert_eq!(evidence.replay_key.id, "req-1");
    assert_eq!(evidence.token_exp, NOW + 120);
    assert_eq!(evidence.request_digest, verified.request_digest());
}

#[test]
fn operator_request_signed_by_unpinned_key_refuses() {
    let wire = signed_wire(&other_operator());
    let error = parse_value(&wire)
        .unwrap()
        .verify(&pinned_key())
        .unwrap_err();
    assert_eq!(
        error,
        RootExchangeError::OperatorRootRequestSignatureInvalid
    );
    assert_eq!(error.oauth_error(), OAuthErrorCode::InvalidRequest);
}

#[test]
fn operator_request_under_another_schema_id_refuses() {
    let mut wire = signed_wire(&operator());
    let (foreign, _) =
        sign_wrapped(&operator(), REVOCATION_REQUEST_SCHEMA, &signing_body(&wire)).unwrap();
    wire["signature"] = json!(foreign.signature.to_hex());
    let error = parse_value(&wire)
        .unwrap()
        .verify(&pinned_key())
        .unwrap_err();
    assert_eq!(
        error,
        RootExchangeError::OperatorRootRequestSignatureInvalid
    );

    let mut renamed = signed_wire(&operator());
    renamed["schema"] = json!(REVOCATION_REQUEST_SCHEMA);
    let error = parse_value(&renamed).unwrap_err();
    assert_eq!(
        error,
        RootExchangeError::OperatorRootRequestMalformed(
            "schema is not chio.operator-root-request.v1"
        )
    );
    assert_eq!(error.oauth_error(), OAuthErrorCode::InvalidRequest);
}

#[test]
fn operator_request_altered_after_signing_refuses() {
    let edits: [(&str, fn(&mut Value)); 7] = [
        ("request_id", |wire| wire["request_id"] = json!("req-2")),
        ("principal", |wire| wire["principal"] = json!("ops:mallory")),
        ("tenant_value", |wire| {
            wire["tenant_value"] = json!("globex")
        }),
        ("tenant_value removed", |wire| {
            wire.as_object_mut().unwrap().remove("tenant_value");
        }),
        ("scope", |wire| {
            wire["scope"] = json!({ "grants": [grant("delete")] });
        }),
        ("holder", |wire| wire["holder"] = json!("caller")),
        ("expires_at", |wire| wire["expires_at"] = json!(NOW + 121)),
    ];
    for (member, edit) in edits {
        let mut wire = signed_wire(&operator());
        edit(&mut wire);
        let error = parse_value(&wire)
            .unwrap()
            .verify(&pinned_key())
            .unwrap_err();
        assert_eq!(
            error,
            RootExchangeError::OperatorRootRequestSignatureInvalid,
            "{member}"
        );
    }
}

#[test]
fn operator_request_sign_without_tenant_refuses() {
    let without_tenant = request(|request| {
        request.as_object_mut().unwrap().remove("tenant_value");
    });
    let error = SignedOperatorRootRequest::sign(without_tenant, &operator()).unwrap_err();
    assert_eq!(error, RootExchangeError::OperatorRootRequestMissingTenant);
    assert_eq!(error.oauth_error(), OAuthErrorCode::InvalidRequest);
}

#[test]
fn signed_operator_request_wire_refusals() {
    let malformed = RootExchangeError::OperatorRootRequestMalformed;
    let wire = signed_wire(&operator());
    let signature = wire["signature"].as_str().unwrap().to_owned();
    let without = |member: &str| {
        let mut edited = wire.clone();
        edited.as_object_mut().unwrap().remove(member);
        serde_json::to_vec(&edited).unwrap()
    };
    let with = |member: &str, value: Value| {
        let mut edited = wire.clone();
        edited[member] = value;
        serde_json::to_vec(&edited).unwrap()
    };
    let mut repeated = serde_json::to_vec(&wire).unwrap();
    repeated.pop();
    repeated.extend_from_slice(br#","request_id":"req-2"}"#);
    let cases = [
        (without("signature"), "signature is missing"),
        (
            with("signature", json!(signature.to_uppercase())),
            "signature is not a canonical hex signature",
        ),
        (
            with("signature", json!(7)),
            "signature is not a canonical hex signature",
        ),
        (
            without("schema"),
            "schema is not chio.operator-root-request.v1",
        ),
        (
            with("schema", json!(1)),
            "schema is not chio.operator-root-request.v1",
        ),
        (
            with("operator_key", json!(pinned_key().to_hex())),
            "body does not have the request shape",
        ),
        (
            without("request_id"),
            "body does not have the request shape",
        ),
        (
            br#"["chio.operator-root-request.v1"]"#.to_vec(),
            "body does not have the request shape",
        ),
        (repeated, "body is not duplicate-free UTF-8 JSON"),
        (
            vec![b' '; MAX_OPERATOR_ROOT_REQUEST_BYTES + 1],
            "body exceeds the size bound",
        ),
    ];
    for (body, reason) in cases {
        let error = SignedOperatorRootRequest::parse(&body).unwrap_err();
        assert_eq!(error, malformed(reason), "{reason}");
        assert_eq!(error.oauth_error(), OAuthErrorCode::InvalidRequest);
    }
}
