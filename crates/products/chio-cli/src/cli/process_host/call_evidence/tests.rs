use super::*;

const ARTIFACT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/process-call-observation/unknown.json"
));
const KEY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/process-call-observation/kernel.pub"
));
const RUNTIME: &str = "714d3643-e7f7-42f9-95b5-6a3a0d734ce8";

#[test]
fn real_denial_after_nonce_issuance_keeps_custody_without_an_admission_projection(
) -> Result<(), CliError> {
    // Retained from the real four-worker shared-family scenario. This worker
    // received its nonce before another worker exhausted the executable budget.
    let key =
        PublicKey::from_hex("b4cdc34f12b6f9b4bca630d008b3c15333b82df760f801516c40c921b9257534")
            .map_err(error)?;
    let signed = crate::receipt_verify::verify_original_receipt(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/process-call-observation/issued-denial.json"
        )),
        &key,
    )?;
    let evidence: Evidence =
        serde_json::from_value(signed.action.parameters.clone()).map_err(error)?;
    verify(
        &signed,
        &evidence,
        &key,
        "36a636ba-8aac-4f8c-be8e-d14cae008583",
    )?;
    let call = crate::process_response_verify::verify_values(
        &evidence.request,
        &evidence.context,
        &evidence.response,
        &key,
    )?;
    assert!(matches!(call.decision, Some(Decision::Deny { .. })));
    assert!(
        call.metadata.as_ref().ok_or_else(|| error("metadata"))?["admission_operation"].is_null()
    );
    let nonce = evidence.nonce.as_ref().ok_or_else(|| error("nonce"))?;
    assert!(nonce.reserved_at_unix_ms.is_none());
    assert_eq!(
        nonce.operation.state,
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    let cap: CapabilityToken = serde_json::from_value(
        evidence.bootstrap.action.parameters["capabilities"]["alice"].clone(),
    )
    .map_err(error)?;
    assert!(super::super::nonce_evidence::verify(
        None,
        &call,
        &evidence.response,
        &cap,
        &key,
        evidence.observed_at_unix_ms,
    )
    .is_err());
    Ok(())
}

#[test]
fn real_interrupted_call_keeps_its_original_signed_custody_reference() -> Result<(), CliError> {
    let text = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/process-call-observation/interrupted.json"
    ));
    let key = PublicKey::from_hex(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/process-call-observation/interrupted-kernel.pub"
        ))
        .trim(),
    )
    .map_err(error)?;
    let signed = crate::receipt_verify::verify_original_receipt(text, &key)?;
    let evidence: Evidence =
        serde_json::from_value(signed.action.parameters.clone()).map_err(error)?;
    verify(
        &signed,
        &evidence,
        &key,
        "a86fa37d-97ec-4e6b-afbd-b178dd9a10a8",
    )?;
    let call = crate::process_response_verify::verify_values(
        &evidence.request,
        &evidence.context,
        &evidence.response,
        &key,
    )?;
    assert!(matches!(call.decision, Some(Decision::Incomplete { .. })));
    let operation = evidence
        .operation
        .as_ref()
        .ok_or_else(|| error("missing fixture operation"))?;
    assert_eq!(
        operation.state,
        AdmissionOperationState::OutcomeUnknownAfterDispatch
    );
    let metadata = call
        .metadata
        .as_ref()
        .ok_or_else(|| error("missing metadata"))?;
    assert!(metadata["admission_operation"].is_null());
    assert_eq!(
        metadata["chio_runtime"]["operation_owned_replay"]["reference"],
        serde_json::to_value(&operation.history[0].history.reference).map_err(error)?
    );
    Ok(())
}

#[test]
fn real_unknown_call_preserves_uncertainty_and_retained_custody() -> Result<(), CliError> {
    let key = PublicKey::from_hex(KEY.trim()).map_err(error)?;
    let signed = crate::receipt_verify::verify_original_receipt(ARTIFACT, &key)?;
    let evidence: Evidence =
        serde_json::from_value(signed.action.parameters.clone()).map_err(error)?;
    verify(&signed, &evidence, &key, RUNTIME)?;
    let call = crate::process_response_verify::verify_values(
        &evidence.request,
        &evidence.context,
        &evidence.response,
        &key,
    )?;
    let cap: CapabilityToken = serde_json::from_value(
        evidence.bootstrap.action.parameters["capabilities"]["carol"].clone(),
    )
    .map_err(error)?;
    let operation = evidence
        .operation
        .as_ref()
        .ok_or_else(|| error("fixture operation missing"))?;
    assert_eq!(
        operation.state,
        AdmissionOperationState::OutcomeUnknownAfterDispatch
    );
    assert!(matches!(&call.decision, Some(Decision::Deny { guard, .. }) if guard == "kernel"));
    assert!(call.metadata.as_ref().ok_or_else(|| error("metadata"))?["chio_runtime"].is_null());

    // These are semantic checks after signature authentication. Mutations must
    // deserialize successfully, so rejection cannot come only from the parser.
    let original = serde_json::to_value(operation).map_err(error)?;
    let history = &original["history"][0];
    let cases = [
        ("/state", json!("completed")),
        ("/state", json!("compensated_before_dispatch")),
        ("/version", json!(999)),
        ("/dispatch_state", json!("not_committed")),
        ("/dispatch_commit", Value::Null),
        ("/dispatch_commit/committed_version", json!(999)),
        ("/terminal_replay", Value::Null),
        (
            "/terminal_replay",
            json!({"receipt": {
                "receipt_id": call.id,
                "projection_digest": original["terminal_replay"]["incident"]["projection_digest"],
            }}),
        ),
        ("/history", json!([])),
        ("/history", json!([history, history])),
        (
            "/history/0/history/disposition",
            json!("released_before_dispatch"),
        ),
        (
            "/history/0/claim/intent/expectationId",
            json!("another-generation"),
        ),
        ("/binding/capability_id", json!("another-capability")),
        ("/binding/request_namespace_digest", json!("0".repeat(64))),
    ];
    for (pointer, replacement) in cases {
        let mut changed = original.clone();
        *changed
            .pointer_mut(pointer)
            .ok_or_else(|| error("fixture mutation target missing"))? = replacement;
        let changed: Operation = serde_json::from_value(changed).map_err(error)?;
        assert!(
            verify_operation(
                Some(&changed),
                &call,
                &cap,
                RUNTIME,
                evidence.observed_at_unix_ms
            )
            .is_err(),
            "accepted unknown-call substitution at {pointer}"
        );
    }
    assert!(verify_operation(None, &call, &cap, RUNTIME, evidence.observed_at_unix_ms).is_err());

    let mut mutations = Vec::new();
    let mut allowed = call.clone();
    allowed.decision = Some(Decision::Allow);
    mutations.push(allowed);
    let mut unrelated_denial = call.clone();
    unrelated_denial.decision = Some(Decision::Deny {
        guard: "unrelated-guard".into(),
        reason: "unrelated denial".into(),
    });
    mutations.push(unrelated_denial);
    let mut completed = call.clone();
    let metadata = completed
        .metadata
        .as_mut()
        .ok_or_else(|| error("metadata"))?;
    metadata["admission_operation"]["tool_outcome_id"] = json!("a".repeat(64));
    metadata["admission_operation"]["tool_outcome_version"] = json!(1);
    mutations.push(completed);
    let mut invented_reference = call.clone();
    invented_reference
        .metadata
        .as_mut()
        .ok_or_else(|| error("metadata"))?["chio_runtime"] = json!({
        "operation_owned_replay": {"reference": original["history"][0]["history"]["reference"]}
    });
    mutations.push(invented_reference);
    for changed in mutations {
        assert!(verify_operation(
            Some(operation),
            &changed,
            &cap,
            RUNTIME,
            evidence.observed_at_unix_ms
        )
        .is_err());
    }

    // A transport interruption can return its original signed custody
    // commitment before the host stores the terminal incident. Unlike the
    // later recovery refusal, that receipt must select the exact retained
    // episode; an arbitrary retained episode cannot substitute for it.
    let mut interrupted = call.clone();
    interrupted.decision = Some(Decision::Incomplete {
        reason: "upstream process exited before responding".into(),
    });
    let metadata = interrupted
        .metadata
        .as_mut()
        .ok_or_else(|| error("metadata"))?;
    metadata
        .as_object_mut()
        .ok_or_else(|| error("metadata object"))?
        .remove("admission_operation");
    let intent = &operation.history[0].history.intent;
    metadata["chio_runtime"] = json!({"operation_owned_replay": {
        "reference": operation.history[0].history.reference,
        "plan_sha256": intent.plan_digest().as_str(),
        "resources_sha256": hash(&intent.resources())?,
    }});
    verify_operation(
        Some(operation),
        &interrupted,
        &cap,
        RUNTIME,
        evidence.observed_at_unix_ms,
    )?;
    for (field, replacement) in [
        ("reference", Value::Null),
        ("plan_sha256", json!("a".repeat(64))),
        ("resources_sha256", json!("a".repeat(64))),
    ] {
        let mut changed = interrupted.clone();
        changed.metadata.as_mut().ok_or_else(|| error("metadata"))?["chio_runtime"]
            ["operation_owned_replay"][field] = replacement;
        assert!(verify_operation(
            Some(operation),
            &changed,
            &cap,
            RUNTIME,
            evidence.observed_at_unix_ms
        )
        .is_err());
    }
    let mut substituted = interrupted.clone();
    substituted
        .metadata
        .as_mut()
        .ok_or_else(|| error("metadata"))?["chio_runtime"]["operation_owned_replay"]["reference"]
        ["claimDigest"] = json!("a".repeat(64));
    assert!(verify_operation(
        Some(operation),
        &substituted,
        &cap,
        RUNTIME,
        evidence.observed_at_unix_ms
    )
    .is_err());
    Ok(())
}
