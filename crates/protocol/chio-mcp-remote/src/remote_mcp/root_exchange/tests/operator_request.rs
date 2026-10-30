//! Signed operator root requests: the signer, the strict decoder, and the
//! verifier under the pinned operator key.

use super::*;
use crate::root_exchange::kinds::operator_key::{
    self, OperatorRootRequest, OperatorRootRequestError, SignedOperatorRootRequest,
    CHIO_OPERATOR_ROOT_REQUEST_SCHEMA, MAX_OPERATOR_ROOT_REQUEST_BYTES, OPERATOR_KEY_ISSUER,
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

fn parse_value(wire: &Value) -> Result<SignedOperatorRootRequest, OperatorRootRequestError> {
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
    assert_eq!(error, OperatorRootRequestError::SignatureInvalid);
    assert_eq!(
        RootExchangeError::from(error.clone()).oauth_error(),
        OAuthErrorCode::InvalidRequest
    );
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
    assert_eq!(error, OperatorRootRequestError::SignatureInvalid);

    let mut renamed = signed_wire(&operator());
    renamed["schema"] = json!(REVOCATION_REQUEST_SCHEMA);
    let error = parse_value(&renamed).unwrap_err();
    assert_eq!(
        error,
        OperatorRootRequestError::Malformed("schema is not chio.operator-root-request.v1")
    );
    assert_eq!(
        RootExchangeError::from(error.clone()).oauth_error(),
        OAuthErrorCode::InvalidRequest
    );
}

#[test]
fn operator_request_altered_after_signing_refuses() {
    let edits: [(&str, fn(&mut Value)); 6] = [
        ("request_id", |wire| wire["request_id"] = json!("req-2")),
        ("principal", |wire| wire["principal"] = json!("ops:mallory")),
        ("tenant_value", |wire| {
            wire["tenant_value"] = json!("globex")
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
            OperatorRootRequestError::SignatureInvalid,
            "{member}"
        );
    }
}

#[test]
fn operator_request_without_tenant_refuses_at_parse() {
    let mut unsigned = request_value(|_| {});
    unsigned.as_object_mut().unwrap().remove("tenant_value");
    let error = OperatorRootRequest::parse(&serde_json::to_vec(&unsigned).unwrap()).unwrap_err();
    assert_eq!(error, OperatorRootRequestError::MissingTenant);
    assert_eq!(
        RootExchangeError::from(error.clone()).oauth_error(),
        OAuthErrorCode::InvalidRequest
    );

    let mut signed = signed_wire(&operator());
    signed.as_object_mut().unwrap().remove("tenant_value");
    assert_eq!(
        parse_value(&signed).unwrap_err(),
        OperatorRootRequestError::MissingTenant
    );

    let mut null_tenant = signed_wire(&operator());
    null_tenant["tenant_value"] = Value::Null;
    assert_eq!(
        parse_value(&null_tenant).unwrap_err(),
        OperatorRootRequestError::Malformed("body does not have the request shape")
    );
}

#[test]
fn signed_operator_request_wire_refusals() {
    let malformed = OperatorRootRequestError::Malformed;
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
        assert_eq!(
            RootExchangeError::from(error.clone()).oauth_error(),
            OAuthErrorCode::InvalidRequest
        );
    }
}

#[test]
fn operator_request_signed_with_explicit_empty_members_verifies_over_the_received_body() {
    let mut body = request_value(|request| {
        request["scope"] = json!({
            "grants": [{
                "server_id": "crm",
                "tool_name": "search",
                "operations": ["invoke"],
                "constraints": []
            }],
            "resource_grants": []
        });
    });
    body["schema"] = json!(CHIO_OPERATOR_ROOT_REQUEST_SCHEMA);
    let (outcome, signed_bytes) =
        sign_wrapped(&operator(), CHIO_OPERATOR_ROOT_REQUEST_SCHEMA, &body).unwrap();
    let mut wire = body.clone();
    wire["signature"] = json!(outcome.signature.to_hex());

    let parsed = parse_value(&wire).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&parsed.to_canonical_json().unwrap()).unwrap(),
        wire
    );
    let verified = parsed.verify(&pinned_key()).unwrap();
    assert_eq!(
        verified.request_digest(),
        Sha256Digest::from_hash(sha256(signed_bytes.as_bytes()))
    );
    assert_eq!(verified.request().scope.grants.len(), 1);
}

fn signed_len(tool_name_len: usize) -> Result<usize, RootExchangeError> {
    let request = request(|request| {
        request["scope"] = json!({ "grants": [{
            "server_id": "crm",
            "tool_name": "t".repeat(tool_name_len),
            "operations": ["invoke"]
        }]});
    });
    SignedOperatorRootRequest::sign(request, &operator())
        .and_then(|signed| signed.to_canonical_json())
        .map(|bytes| bytes.len())
}

#[test]
fn operator_request_sign_refuses_a_signed_form_over_the_size_bound() {
    let base = signed_len(1).unwrap();
    let at_bound = 1 + (MAX_OPERATOR_ROOT_REQUEST_BYTES - base);
    assert_eq!(
        signed_len(at_bound).unwrap(),
        MAX_OPERATOR_ROOT_REQUEST_BYTES
    );

    let request = request(|request| {
        request["scope"] = json!({ "grants": [{
            "server_id": "crm",
            "tool_name": "t".repeat(at_bound),
            "operations": ["invoke"]
        }]});
    });
    let signed = SignedOperatorRootRequest::sign(request, &operator()).unwrap();
    SignedOperatorRootRequest::parse(&signed.to_canonical_json().unwrap())
        .unwrap()
        .verify(&pinned_key())
        .unwrap();

    assert_eq!(
        signed_len(at_bound + 1).unwrap_err(),
        OperatorRootRequestError::Malformed("signed request exceeds the size bound")
    );
}

mod properties {
    use proptest::prelude::*;

    use super::*;

    fn identifier() -> impl Strategy<Value = String> {
        "[a-z0-9:._-]{1,64}"
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn parse_refuses_arbitrary_bytes_with_a_typed_refusal(
            bytes in proptest::collection::vec(any::<u8>(), 0..512)
        ) {
            if let Err(error) = SignedOperatorRootRequest::parse(&bytes) {
                prop_assert!(matches!(
                    error,
                    OperatorRootRequestError::Malformed(_)
                        | OperatorRootRequestError::MissingTenant
                ));
            }
        }

        #[test]
        fn signed_requests_round_trip_byte_for_byte(
            request_id in identifier(),
            principal in identifier(),
            tenant in identifier(),
            caller_held in any::<bool>(),
            lifetime in 1u64..1_000_000,
        ) {
            let value = request_value(|request| {
                request["request_id"] = json!(&request_id);
                request["principal"] = json!(&principal);
                request["tenant_value"] = json!(&tenant);
                request["holder"] = json!(if caller_held { "caller" } else { "edge_session" });
                request["expires_at"] = json!(NOW + lifetime);
            });
            let request = OperatorRootRequest::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
            let bytes = SignedOperatorRootRequest::sign(request, &operator())
                .unwrap()
                .to_canonical_json()
                .unwrap();
            let parsed = SignedOperatorRootRequest::parse(&bytes).unwrap();
            prop_assert_eq!(parsed.to_canonical_json().unwrap(), bytes.clone());
            let verified = parsed.verify(&pinned_key()).unwrap();
            prop_assert_eq!(verified.request().tenant_value.as_str(), tenant.as_str());
        }
    }
}

/// The schema corpus under `spec/.../root_authority/examples` and the Rust
/// decoder agree: the valid request decodes, and each invalid one refuses
/// with its typed refusal.
#[test]
fn operator_request_schema_corpus_matches_the_decoder() {
    let examples = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-wire/v1/root_authority/examples");
    let read = |kind: &str, name: &str| std::fs::read(examples.join(kind).join(name)).unwrap();

    let valid = SignedOperatorRootRequest::parse(&read(
        "valid",
        "operator-root-request.constrained-scope.json",
    ))
    .unwrap();
    assert_eq!(
        valid.verify(&pinned_key()).unwrap_err(),
        OperatorRootRequestError::SignatureInvalid
    );

    for (name, expected) in [
        (
            "operator-root-request.missing-tenant.json",
            OperatorRootRequestError::MissingTenant,
        ),
        (
            "operator-root-request.unknown-member.json",
            OperatorRootRequestError::Malformed("body does not have the request shape"),
        ),
    ] {
        assert_eq!(
            SignedOperatorRootRequest::parse(&read("invalid", name)).unwrap_err(),
            expected,
            "{name}"
        );
    }
}
