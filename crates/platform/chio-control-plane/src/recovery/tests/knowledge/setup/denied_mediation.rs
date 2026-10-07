//! The refused self-test leg must exercise native policy with the agent's scope.
use super::*;

pub(super) fn retained_receipts(
    f: &KnowledgeFixture,
) -> TestResult<Vec<chio_core_types::receipt::body::ChioReceipt>> {
    let connection = rusqlite::Connection::open(f.f.path.join("receipts.db"))?;
    let mut query =
        connection.prepare("SELECT raw_json FROM chio_tool_receipts ORDER BY receipt_id")?;
    let rows = query.query_map([], |row| row.get::<_, String>(0))?;
    rows.map(|row| {
        let raw = row?;
        // The receipt store's typed writer preserves serde field order.
        // Signing independently canonicalizes the exact closed receipt body.
        let value = chio_core_types::canonical::parse_signed_json(&raw)?;
        let receipt: chio_core_types::receipt::body::ChioReceipt = serde_json::from_value(value)?;
        assert_eq!(
            serde_json::to_string(&receipt)?,
            raw,
            "the owning receipt store must retain its exact typed writer bytes"
        );
        assert!(receipt.verify_signature()?);
        assert!(receipt.action.verify_hash()?);
        assert_eq!(receipt.kernel_key, f.f.kernel.receipt_signing_public_key());
        Ok(receipt)
    })
    .collect()
}

// Diagnostic values are fixed vocabulary and booleans. Never print receipt
// reasons, request data, capabilities, arbitrary guard names or guard details.
fn denied_native_policy_category(details: Option<&str>) -> &'static str {
    match details {
        Some("state_overflow") => "state_overflow",
        Some("state_changed") => "state_changed",
        Some("invalid_manifest") => "invalid_manifest",
        Some("declassification_binding_mismatch") => "declassification_binding_mismatch",
        Some("declassification_purpose_denied") => "declassification_purpose_denied",
        Some("declassification_not_yet_valid") => "declassification_not_yet_valid",
        Some("declassification_expired") => "declassification_expired",
        Some("declassification_untrusted_authority") => "declassification_untrusted_authority",
        Some("unexpected_declassification") => "unexpected_declassification",
        Some("declassification_replay") => "declassification_replay",
        Some("declassification_store_failure") => "declassification_store_failure",
        Some("classifier_failure") => "classifier_failure",
        Some("classifier_binding_mismatch") => "classifier_binding_mismatch",
        Some("missing_policy_clearance") => "missing_policy_clearance",
        Some("missing_manifest_clearance") => "missing_manifest_clearance",
        Some("top_source") => "top_source",
        Some("top_clearance") => "top_clearance",
        Some("policy_flow_violation") => "policy_flow_violation",
        Some("manifest_flow_violation") => "manifest_flow_violation",
        Some(_) => "unrecognized",
        None => "absent",
    }
}

fn denied_probe_result_class(
    error: Option<&crate::recovery::RecoveryRuntimeError>,
) -> &'static str {
    use crate::recovery::RecoveryRuntimeError;
    match error {
        None => "success",
        Some(RecoveryRuntimeError::AuthorityDenied) => "authority_denied",
        Some(RecoveryRuntimeError::UncoveredMediation) => "uncovered_mediation",
        Some(RecoveryRuntimeError::Unavailable) => "unavailable",
        Some(RecoveryRuntimeError::Busy) => "busy",
        Some(RecoveryRuntimeError::Conflict) => "conflict",
        Some(_) => "other_closed_refusal",
    }
}

fn denied_native_custody_phase(
    f: &KnowledgeFixture,
    benign: &chio_kernel::admission_operation::AdmissionOperationV1,
    denied_request: &ToolCallRequest,
) -> TestResult<&'static str> {
    let connection = rusqlite::Connection::open_with_flags(
        f.f.path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    // This is an observation of this test's exact authenticated benign
    // namespace, not the global request-id selector or a readiness proof.
    let mut query = connection.prepare(
        "SELECT operation_id FROM admission_operations
         WHERE request_namespace_digest=?1 AND request_id=?2 LIMIT 2",
    )?;
    let identities = query
        .query_map(
            rusqlite::params![
                benign.binding().request_namespace_digest().as_str(),
                denied_request.request_id,
            ],
            |row| row.get::<_, String>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    let [identity] = identities.as_slice() else {
        return Ok(if identities.is_empty() {
            "no_native_original"
        } else {
            "ambiguous_native_original"
        });
    };
    let operation_id =
        chio_kernel::admission_operation::AdmissionOperationId::from_persisted(identity)?;
    let stored = f
        .f
        .authority
        .admission_operation_store()
        .load_retained_tool_request(&operation_id, &f.f.authority.mutation_fence(), now_ms()?)?;
    let Some((operation, retained)) = stored else {
        return Ok("native_original_absent_after_selector");
    };
    if retained.validate_request_material(denied_request).is_err() {
        return Ok("native_original_material_mismatch");
    }
    Ok(match operation.state() {
        AdmissionOperationState::CompensatedBeforeDispatch => "compensated_before_dispatch",
        AdmissionOperationState::CapturePending => "capture_pending",
        AdmissionOperationState::Completed => "completed",
        AdmissionOperationState::OutcomeUnknownAfterDispatch => "outcome_unknown_after_dispatch",
        _ => "other_native_state",
    })
}

#[tokio::test]
async fn setup_denied_counterpart_preserves_agent_authority_and_proves_native_policy_refusal(
) -> TestResult {
    let f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    let workflow = Box::pin(f.f.ready()).await?;
    let service = setup(&f, &workflow)?;
    let before = retained_receipts(&f)?;
    let calls = f.f.process.process("root")?.tree_calls;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let inspect = f.actor(RecoveryPermission::Inspect)?;
    let prepared = store
        .setup_preparation(&inspect, &fence, now_ms()?)
        .map_err(|error| format!("setup denied phase=before public probe preparation: {error}"))?;
    let result = service.probe(&f.f.control, &workflow).await;
    let denied: Vec<_> = retained_receipts(&f)?
        .into_iter()
        .filter(|receipt| receipt.is_denied() && !before.iter().any(|old| old.id == receipt.id))
        .collect();
    assert_eq!(
        denied.len(),
        1,
        "setup denied phase=new native counterpart receipt; public result={:?}",
        result.as_ref().err(),
    );
    let receipt = denied.first().ok_or("signed native policy denial")?;
    assert!(receipt.verify_signature()?);
    assert_eq!(receipt.kernel_key, f.f.kernel.receipt_signing_public_key());
    let record = f.f.record(&workflow)?;
    let benign_id = record
        .native_link
        .as_ref()
        .ok_or("setup denied phase=benign native link")?;
    let (benign_operation, benign_retained) = store
        .load_retained_tool_request(
            &chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
                benign_id.as_str(),
            )?,
            &fence,
            now_ms()?,
        )?
        .ok_or("setup denied phase=benign retained native request")?;
    assert_eq!(benign_operation.state(), AdmissionOperationState::Completed);
    let mut actual_counterpart = benign_retained.request_for_revalidation().clone();
    actual_counterpart.request_id = prepared.probe.denied_command.as_str().to_owned();
    actual_counterpart.declassification_grant = None;
    actual_counterpart.execution_nonce = None;
    let mut expected = record.seed.clone();
    expected.request_id = actual_counterpart.request_id.clone();
    expected.declassification_grant = None;
    expected.execution_nonce = None;
    assert_eq!(
        chio_core_types::canonical_json_bytes(&actual_counterpart)?,
        chio_core_types::canonical_json_bytes(&expected)?,
        "setup denied phase=workflow continuation must preserve actual benign native caller material",
    );
    assert_eq!(receipt.capability_id, actual_counterpart.capability.id);
    assert_ne!(receipt.capability_id, f.f.control.id);
    assert_eq!(receipt.action.parameters, actual_counterpart.arguments);
    assert_eq!(
        receipt.action.parameter_hash,
        benign_operation.binding().action_parameter_hash().as_str()
    );
    assert_eq!(receipt.tool_server, f.f.seed.server_id);
    assert_eq!(receipt.tool_name, f.f.seed.tool_name);
    let native_evidence = receipt
        .evidence
        .iter()
        .filter(|guard| guard.guard_name == "native-flow-resolver")
        .collect::<Vec<_>>();
    let native_categories = native_evidence
        .iter()
        .map(|guard| denied_native_policy_category(guard.details.as_deref()))
        .collect::<Vec<_>>();
    let raw_metadata = receipt
        .metadata
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .and_then(|object| {
            object.get(chio_kernel::admission_operation::ADMISSION_RECEIPT_METADATA_KEY)
        });
    let native_metadata = raw_metadata.and_then(|value| {
        serde_json::from_value::<chio_kernel::admission_operation::AdmissionReceiptMetadataV1>(
            value.clone(),
        )
        .ok()
    });
    eprintln!(
        "setup denied phase=before native-policy proof; denied={}; public_result={}; \
         owner_count={}; owner_false_count={}; categories={:?}; \
         signed_metadata_present={}; signed_metadata_decoded={}; \
         signed_metadata_compensated={}; native_custody={}",
        receipt.is_denied(),
        denied_probe_result_class(result.as_ref().err()),
        native_evidence.len(),
        native_evidence
            .iter()
            .filter(|guard| !guard.verdict)
            .count(),
        native_categories,
        raw_metadata.is_some(),
        native_metadata.is_some(),
        native_metadata.as_ref().is_some_and(|metadata| {
            metadata.projected_state == AdmissionOperationState::CompensatedBeforeDispatch
        }),
        denied_native_custody_phase(&f, &benign_operation, &actual_counterpart)
            .unwrap_or("native_custody_observation_refused"),
    );
    assert!(
        receipt.evidence.iter().any(|guard| {
            guard.guard_name == "native-flow-resolver"
                && !guard.verdict
                && guard.details.as_deref() == Some("policy_flow_violation")
        }),
        "the signed denial must identify the native policy owner and its closed refusal category"
    );
    use chio_kernel::admission_operation::{
        AdmissionCompensationStatus, AdmissionReceiptMetadataV1, AdmissionReceiptSchema,
        AdmissionTerminalReplay, ADMISSION_RECEIPT_METADATA_KEY,
    };
    let metadata = receipt
        .metadata
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .and_then(|value| value.get(ADMISSION_RECEIPT_METADATA_KEY))
        .ok_or("setup denied phase=signed compensated native metadata")?;
    let metadata: AdmissionReceiptMetadataV1 = chio_core_types::recovery::decode_contract(
        &chio_core_types::canonical_json_bytes(metadata)?,
    )?;
    let (operation, retained) = store
        .load_retained_tool_request(&metadata.operation_id, &fence, now_ms()?)?
        .ok_or("setup denied phase=exact signed native operation")?;
    assert_eq!(metadata.schema, AdmissionReceiptSchema::V1);
    assert_eq!(metadata.operation_id, *operation.binding().operation_id());
    assert_eq!(metadata.request_id, *operation.binding().request_id());
    assert_eq!(
        metadata.request_namespace_digest,
        *operation.binding().request_namespace_digest()
    );
    assert_eq!(operation.binding().request_namespace_digest(), benign_operation.binding().request_namespace_digest(),
        "setup denied phase=the two real native operations must share the owning sessionless namespace");
    assert_eq!(
        metadata.request_binding_hash,
        *operation.binding().request_binding_hash()
    );
    assert_eq!(metadata.projected_operation_version, operation.version());
    assert_eq!(metadata.projected_state, operation.state());
    assert_eq!(
        metadata.projected_dispatch_state,
        operation.dispatch_state()
    );
    assert!(metadata.retained_dispatch_commit.is_none());
    assert_eq!(
        metadata.compensation_status,
        AdmissionCompensationStatus::CompensatedBeforeDispatch
    );
    assert!(metadata.tool_outcome_id.is_none() && metadata.tool_outcome_version.is_none());
    assert!(matches!(
        operation.terminal_replay(),
        Some(AdmissionTerminalReplay::Incident { .. })
    ));
    retained
        .validate_request_material(&actual_counterpart)
        .map_err(|error| format!("setup denied phase=exact counterpart request: {error}"))?;
    let selected = f.f.kernel.recovery_deployment(f.f.runtime.scope())?;
    retained
        .validate_native_security_context(&selected.security_context)
        .map_err(|error| format!("setup denied phase=original native context: {error}"))?;
    retained
        .validate_native_security_authority(&selected.native_authority)
        .map_err(|error| format!("setup denied phase=original native authority: {error}"))?;
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let (raw, updated_at): (Vec<u8>, i64) = connection.query_row(
        "SELECT p.projection_json,o.updated_at_unix_ms \
         FROM admission_operation_terminal_projections p \
         JOIN admission_operations o ON o.operation_id=p.operation_id WHERE p.operation_id=?1",
        [metadata.operation_id.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    #[derive(serde::Deserialize)]
    struct CompensationProjection {
        context: chio_kernel::admission_operation::AdmissionProjectionContext,
    }
    let projection: CompensationProjection = serde_json::from_slice(&raw)?;
    let context = projection.context;
    context.validate()?;
    assert_eq!(context.operation_id, metadata.operation_id);
    assert_eq!(context.request_id, metadata.request_id);
    assert_eq!(
        context.expected_operation_version.checked_add(1),
        Some(operation.version())
    );
    assert_eq!(
        context.trusted_time_unix_ms, metadata.trusted_time_unix_ms,
        "setup denied phase=signed native projection time"
    );
    assert_eq!(
        u64::try_from(updated_at)?,
        context.trusted_time_unix_ms,
        "setup denied phase=physical native projection time"
    );
    assert_eq!(metadata.coordinator_lease_id, context.coordinator_lease_id);
    assert_eq!(
        metadata.coordinator_lease_epoch,
        context.coordinator_lease_epoch
    );
    assert_eq!(metadata.store_fence, context.store_fence);
    assert_eq!(
        receipt.timestamp,
        context.trusted_time_unix_ms / 1_000,
        "setup denied phase=public receipt time uses confirmed projection"
    );
    assert_eq!(
        SourceDigest::from_bytes(recovery_digest(
            chio_core_types::recovery::RecoveryDigestDomain::ServingFence,
            &context.store_fence,
        )?),
        prepared.previous_serving_fence,
        "setup denied phase=compensation under the selected setup writer",
    );
    let probe = result.map_err(|error| {
        format!(
            "setup denied phase=public probe after independently observed native custody: {error}"
        )
    })?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    assert_eq!(probe.body(), &prepared.probe);
    assert_eq!(
        chio_core_types::canonical_json_bytes(retained.request_for_revalidation())?,
        chio_core_types::canonical_json_bytes(&expected)?
    );
    assert_eq!(external_count(&f.f.path)?, 1);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    Ok(())
}

#[tokio::test]
async fn setup_a_signed_scope_denial_cannot_substitute_for_pinned_native_mediation() -> TestResult {
    let f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    let workflow = Box::pin(f.f.ready()).await?;
    let _service = setup(&f, &workflow)?;
    let actor = f.f.kernel.authenticate_recovery_actor(
        f.f.runtime.scope(),
        &f.f.control,
        RecoveryPermission::Inspect,
    )?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let prepared = store.setup_preparation(&actor, &fence, now_ms()?)?;
    let calls = f.f.process.process("root")?.tree_calls;
    let benign = Box::pin(f.f.runtime.execute_command(&f.f.control, &prepared.command))
        .await?
        .original_response
        .ok_or("completed native self-test projection")?
        .receipt;
    let mut request = f.f.record(&workflow)?.seed;
    request.request_id = "unrelated-signed-scope-denial".into();
    request.capability = f.f.control.clone();
    request.declassification_grant = None;
    request.execution_nonce = None;
    let unrelated = Box::pin(f.f.kernel.evaluate_tool_call(&request)).await?;
    assert!(unrelated.receipt.is_denied());
    assert!(unrelated.receipt.verify_signature()?);
    assert!(!unrelated
        .receipt
        .evidence
        .iter()
        .any(|guard| { guard.guard_name == "native-flow-resolver" && !guard.verdict }));
    request.request_id = prepared.probe.denied_command.as_str().into();
    let probe = SignedRecoverySetupProbeV1::sign(prepared.probe, &Keypair::from_seed(&[211; 32]))?;
    assert!(
        store
            .commit_setup_probe(
                &actor,
                &chio_store_sqlite::admission_operation_store::NativeSetupProbeEvidenceV1 {
                    probe: &probe,
                    benign: &benign,
                    denied_request: &request,
                    denied: &unrelated.receipt,
                },
                &fence,
                now_ms()?,
            )
            .is_err(),
        "a genuine signed capability refusal is not evidence of the pinned native-policy path"
    );
    assert!(store
        .setup_preparation(&actor, &fence, now_ms()?)?
        .signed_probe
        .is_none());
    assert_eq!(external_count(&f.f.path)?, 1);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    Ok(())
}

#[tokio::test]
async fn setup_stale_native_observation_cannot_substitute_for_the_denied_policy_leg() -> TestResult
{
    let f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    let workflow = Box::pin(f.f.ready()).await?;
    let _service = setup(&f, &workflow)?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let inspector = f.actor(RecoveryPermission::Inspect)?;
    let prepared = store.setup_preparation(&inspector, &fence, now_ms()?)?;
    let calls = f.f.process.process("root")?.tree_calls;
    let benign = Box::pin(f.f.runtime.execute_command(&f.f.control, &prepared.command))
        .await?
        .original_response
        .ok_or("stale native observation benign original result")?;
    assert!(benign.receipt.is_allowed() && benign.receipt.verify_signature()?);
    assert_eq!(external_count(&f.f.path)?, 1);
    let record = f.f.record(&workflow)?;
    let selected = f.f.kernel.recovery_deployment(f.f.runtime.scope())?;
    let refreshed =
        f.f.kernel
            .refresh_native_security_context(&selected.security_context)?;
    assert!(selected
        .security_context
        .as_v1()
        .flow_state_generation()
        .is_none());
    assert!(refreshed.as_v1().flow_state_generation().is_some());
    assert_eq!(
        recovery_flow_key(&refreshed),
        recovery_flow_key(&selected.security_context)
    );
    assert_eq!(
        refreshed.as_v1().context_generation(),
        selected.security_context.as_v1().context_generation(),
    );
    let operation_id = record
        .native_link
        .as_ref()
        .ok_or("stale observation benign link")?;
    let (operation, retained) = store
        .load_retained_tool_request(
            &chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
                operation_id.as_str(),
            )?,
            &fence,
            now_ms()?,
        )?
        .ok_or("stale observation real benign custody")?;
    assert_eq!(operation.state(), AdmissionOperationState::Completed);
    retained.validate_native_security_context(&selected.security_context)?;
    retained.validate_native_security_context(&refreshed)?;
    retained.validate_native_security_authority(&selected.native_authority)?;
    let mut request = retained.request_for_revalidation().clone();
    request.request_id = prepared.probe.denied_command.as_str().to_owned();
    request.declassification_grant = None;
    request.execution_nonce = None;
    let stale = Box::pin(
        f.f.kernel
            .evaluate_tool_call_with_security_context(&request, &selected.security_context),
    )
    .await?;
    assert!(stale.receipt.is_denied() && stale.receipt.verify_signature()?);
    assert_eq!(
        stale.receipt.capability_id,
        retained.request_for_revalidation().capability.id
    );
    assert_eq!(stale.receipt.action.parameters, request.arguments);
    assert!(
        stale.receipt.evidence.iter().all(|evidence| {
            evidence.guard_name != "native-flow-resolver"
                || evidence.details.as_deref() != Some("policy_flow_violation")
        }),
        "a stale observation refusal is not a policy-flow proof"
    );
    assert_eq!(
        denied_native_custody_phase(&f, &operation, &request)?,
        "compensated_before_dispatch"
    );
    assert!(store
        .commit_setup_probe(
            &inspector,
            &NativeSetupProbeEvidenceV1 {
                probe: &SignedRecoverySetupProbeV1::sign(
                    prepared.probe.clone(),
                    &Keypair::from_seed(&[211; 32])
                )?,
                benign: &benign.receipt,
                denied_request: &request,
                denied: &stale.receipt,
            },
            &fence,
            now_ms()?,
        )
        .is_err());
    assert!(store
        .setup_preparation(&inspector, &fence, now_ms()?)?
        .signed_probe
        .is_none());
    assert_eq!(external_count(&f.f.path)?, 1);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    Ok(())
}
