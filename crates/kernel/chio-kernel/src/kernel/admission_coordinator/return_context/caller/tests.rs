use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    kernel: ChioKernel,
    admission: DurableToolAdmission,
    frame: AdmissionCallerDispatchContextV1,
    nonce: crate::execution_nonce::SignedExecutionNonce,
}

#[path = "tests/fixture.rs"]
mod fixture;
use fixture::fixture;

#[path = "tests/participants.rs"]
mod participants;

#[path = "tests/custody.rs"]
mod custody;

#[test]
fn caller_return_codec_keeps_frozen_facts_without_credentials_or_return_observations() -> TestResult
{
    let mut fixture = fixture()?;
    let before = fixture.kernel.decode_caller_return_context(
        &fixture.admission,
        &fixture.frame,
        current_unix_timestamp_ms(),
    )?;
    let private = std::str::from_utf8(fixture.frame.kernel_context_json())?;
    assert!(!private.contains("private-request-input"));
    assert!(!private.contains("returned-after-context-capture"));
    assert!(!private.contains(&serde_json::to_string(&fixture.nonce.signature)?));
    let metadata = before.metadata_with_return_observation(None);
    fixture.kernel.config.memory_budget.max_stream_chunks = I_JSON_MAX_SAFE_INTEGER + 1;
    assert!(fixture.kernel.durable_stream_limits().is_err());
    let restored = fixture.kernel.decode_caller_return_context(
        &fixture.admission,
        &fixture.frame,
        current_unix_timestamp_ms(),
    )?;
    assert_eq!(restored.stream_limits, before.stream_limits);
    assert_eq!(
        restored.receipt_signing_identity,
        before.receipt_signing_identity
    );
    assert_eq!(
        before
            .receipt_signing_identity
            .as_ref()
            .ok_or("frozen signer")?
            .public_key(),
        &fixture.kernel.receipt_signing_public_key()
    );
    assert_eq!(
        restored.pre_invocation_guard_evidence,
        before.pre_invocation_guard_evidence
    );
    assert_eq!(restored.metadata_with_return_observation(None), metadata);
    assert_eq!(
        restored.request_material_digest,
        before.request_material_digest
    );
    Ok(())
}

#[test]
fn caller_return_codec_rejects_private_payload_schema_identity_grant_and_limit_substitution(
) -> TestResult {
    let fixture = fixture()?;
    let original: serde_json::Value = serde_json::from_slice(fixture.frame.kernel_context_json())?;
    fixture.kernel.decode_caller_return_payload(
        &fixture.admission,
        fixture.frame.kernel_context_json(),
        current_unix_timestamp_ms(),
    )?;
    let mutations = [
        ("schema", serde_json::json!("unknown")),
        ("receipt_signing_identity", serde_json::Value::Null),
        (
            "kernel_public_key",
            serde_json::json!(chio_core::Keypair::generate().public_key()),
        ),
        ("frozen_at_unix_ms", serde_json::json!(0)),
        (
            "frozen_at_unix_ms",
            serde_json::json!(I_JSON_MAX_SAFE_INTEGER),
        ),
        ("operation_id", serde_json::json!("a".repeat(64))),
        ("request_binding_hash", serde_json::json!("b".repeat(64))),
        ("request_material_digest", serde_json::json!("c".repeat(64))),
        ("request_id", serde_json::json!("another-request")),
        ("matched_grant_index", serde_json::json!(1)),
        (
            "stream_limits",
            serde_json::json!({"max_total_bytes": I_JSON_MAX_SAFE_INTEGER + 1, "max_chunks": 1, "max_duration_secs": 1}),
        ),
        ("federation_context_json", serde_json::json!("{}")),
        (
            "runtime_participant_ledger_digest",
            serde_json::json!("d".repeat(64)),
        ),
        ("unknown_field", serde_json::json!(true)),
        (
            "security_invocation_context",
            serde_json::json!({"version": "v1", "context": {
                "tenantId": "tenant", "sessionId": "session", "principalId": "not-the-admitted-principal",
                "isolationEpochId": "epoch", "lineageRootId": "wrong-root", "contextGeneration": 1, "flowStateGeneration": null
            }}),
        ),
    ];
    for (field, value) in mutations {
        let mut mutated = original.clone();
        mutated[field] = value;
        let bytes = canonical_json_bytes(&mutated)?;
        assert!(
            fixture
                .kernel
                .decode_caller_return_payload(
                    &fixture.admission,
                    &bytes,
                    current_unix_timestamp_ms()
                )
                .is_err(),
            "accepted modified {field}"
        );
    }
    Ok(())
}

#[test]
fn caller_return_codec_keeps_legacy_identity_absence_explicit() -> TestResult {
    let fixture = fixture()?;
    let mut payload: serde_json::Value =
        serde_json::from_slice(fixture.frame.kernel_context_json())?;
    payload
        .as_object_mut()
        .ok_or("caller object")?
        .remove("receipt_signing_identity");
    assert!(
        fixture
            .kernel
            .decode_caller_return_payload(
                &fixture.admission,
                &canonical_json_bytes(&payload)?,
                current_unix_timestamp_ms(),
            )
            .is_err(),
        "current frames require a frozen identity"
    );
    payload["schema"] = serde_json::json!(LEGACY_SCHEMA);
    payload
        .as_object_mut()
        .ok_or("caller object")?
        .remove("participant_custody");
    payload
        .as_object_mut()
        .ok_or("caller object")?
        .remove("participants");
    let legacy = fixture.kernel.decode_caller_return_payload(
        &fixture.admission,
        &canonical_json_bytes(&payload)?,
        current_unix_timestamp_ms(),
    )?;
    assert!(legacy.receipt_signing_identity.is_none());
    payload["receipt_signing_identity"] =
        serde_json::to_value(fixture.kernel.freeze_receipt_signing_identity()?)?;
    assert!(
        fixture
            .kernel
            .decode_caller_return_payload(
                &fixture.admission,
                &canonical_json_bytes(&payload)?,
                current_unix_timestamp_ms(),
            )
            .is_err(),
        "legacy frames cannot smuggle a signing selection"
    );
    Ok(())
}

#[test]
fn caller_return_codec_rejects_noncanonical_oversized_and_unbound_frames() -> TestResult {
    let mut fixture = fixture()?;
    for bytes in [
        Vec::new(),
        vec![b' '; AdmissionCallerDispatchContextV1::MAX_KERNEL_CONTEXT_BYTES + 1],
        [b" ".as_slice(), fixture.frame.kernel_context_json()].concat(),
    ] {
        assert!(fixture
            .kernel
            .decode_caller_return_payload(&fixture.admission, &bytes, current_unix_timestamp_ms())
            .is_err());
    }
    let retained = fixture.admission.retained_request.take();
    assert!(fixture
        .kernel
        .decode_caller_return_context(
            &fixture.admission,
            &fixture.frame,
            current_unix_timestamp_ms()
        )
        .is_err());
    fixture.admission.retained_request = retained;
    fixture.kernel.config.keypair = chio_core::Keypair::generate();
    assert!(fixture
        .kernel
        .decode_caller_return_context(
            &fixture.admission,
            &fixture.frame,
            current_unix_timestamp_ms()
        )
        .is_err());
    Ok(())
}

#[test]
fn caller_return_codec_rejects_individually_valid_but_unadmitted_security_context() -> TestResult {
    let fixture = fixture()?;
    let request = fixture
        .admission
        .retained_request
        .as_ref()
        .ok_or("original request")?
        .request_for_revalidation();
    let context = SecurityInvocationContext::v1(crate::SecurityInvocationContextV1::new(
        chio_security_types::ports::TenantId::new("injected-tenant")?,
        chio_security_types::ports::SessionId::new("injected-session")?,
        chio_security_types::PrincipalId::new(request.agent_id.clone())?,
        chio_security_types::ports::IsolationEpochId::new("injected-epoch")?,
        chio_security_types::ports::LineageId::new(request.capability.id.clone())?,
        1,
    ));
    fixture
        .kernel
        .validate_security_invocation_context_binding(request, Some(&context), None)?;
    let mut payload: serde_json::Value =
        serde_json::from_slice(fixture.frame.kernel_context_json())?;
    payload["security_invocation_context"] = serde_json::to_value(context)?;
    assert!(fixture
        .kernel
        .decode_caller_return_payload(
            &fixture.admission,
            &canonical_json_bytes(&payload)?,
            current_unix_timestamp_ms(),
        )
        .is_err());
    Ok(())
}
