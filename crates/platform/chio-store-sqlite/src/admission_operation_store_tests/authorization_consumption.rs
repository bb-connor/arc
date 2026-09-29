//! Signed source verification, atomic terminal consumption and durable replay.
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chio_core::capability::scope::MonetaryAmount;
use chio_core::receipt::{
    body::{ChioReceipt, ChioReceiptBody},
    decision::{Decision, ToolCallAction},
};
use chio_kernel::admission_operation::{
    AdmissionCompensationStatus, AdmissionCompletedProjection, AdmissionDispatchState,
    AdmissionReceiptMetadataV1, AdmissionReceiptSchema, VerifiedAdmissionReceipt,
    VerifiedAuthorizationReceiptConsumption, ADMISSION_RECEIPT_METADATA_KEY,
};
use chio_kernel::receipt_store::AuthorizationReceiptConsumption;
use chio_kernel::tool_outcome::test_support::{
    prepared_evaluation, record_external_step, record_pure_step, resolve, returned_value,
};
use chio_kernel::tool_outcome::{SettlementDispositionV1, ToolOutcomeTerminalEvidenceV1};

struct Candidate {
    operation: AdmissionOperationV1,
    envelope: SignedAdmissionTerminalProjectionV1,
}

fn signer() -> Keypair {
    Keypair::from_seed(&[0x71; 32])
}
fn claimant() -> String {
    format!("kernel:{}", signer().public_key().to_hex())
}

fn candidate(
    fixture: &Fixture,
    suffix: &str,
    at: u64,
    claimant: &str,
) -> AnchoredTestResult<Candidate> {
    let action = ToolCallAction::from_parameters(serde_json::json!({}))?;
    let action_parameter_hash =
        AdmissionDigest::try_new("action_parameter_hash", action.parameter_hash.clone())?;
    let requirements = AdmissionParticipantRequirements {
        broker_attempt: true,
        budget_capture: true,
        authorization_consumption: true,
        ..AdmissionParticipantRequirements::NONE
    };
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::ToolDispatch,
        namespace: AuthenticatedRequestNamespace::for_local_system(identifier(
            "coordinator_authority_id",
            &format!("authorization-authority-{suffix}"),
        ))?,
        request_id: identifier("request_id", "authorization-request"),
        capability_id: identifier("capability_id", "authorization-capability"),
        authorization_capability_hash: digest("authorization_capability_hash", 'a'),
        request_binding: AdmissionRequestBindingV1::new_with_action_parameter_hash(
            digest("immutable_request_hash", 'b'),
            action_parameter_hash,
            requirements,
        )?,
        policy_hash: digest("policy_hash", 'c'),
        effect_class: SideEffectClass::Monetary,
    })?;
    let mut operation = AdmissionOperationV1::prepare(binding, fixture.fence.owner_epoch)?;
    fixture.store.begin(&operation, &fixture.fence, at)?;
    let transitions = [
        (
            AdmissionOperationState::BrokerAttemptRegistered,
            vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
                &operation,
                &format!("obligation-attempt-{suffix}"),
            ))],
        ),
        (
            AdmissionOperationState::BudgetAuthorized,
            vec![AdmissionAttachment::BudgetHoldId(identifier(
                "budget_hold_id",
                &format!("obligation-hold-{suffix}"),
            ))],
        ),
        (AdmissionOperationState::ReadyToDispatch, Vec::new()),
        (AdmissionOperationState::CapturePending, Vec::new()),
        (AdmissionOperationState::DispatchCommitted, Vec::new()),
    ];
    for (state, attachments) in transitions {
        let recovery = claim(fixture, &operation, claimant, at);
        operation = fixture
            .store
            .compare_and_swap(&command(&operation, recovery, attachments, state, None), at)?
            .into_operation();
    }

    let amount = MonetaryAmount {
        units: 37,
        currency: "USD".to_owned(),
    };
    let (_, returned) = returned_value(
        &operation,
        fixture.fence.clone(),
        at,
        serde_json::json!({ "result": "ok" }),
        None,
    )?;
    let evaluation = prepared_evaluation(&operation, &returned, at)
        .and_then(|value| record_pure_step(&value))
        .and_then(|value| record_external_step(&value, at))?;
    let (evaluation, outcome) = resolve(
        &returned,
        &evaluation,
        SettlementDispositionV1::Capture {
            amount: amount.clone(),
        },
    )?;
    let recovery = claim(fixture, &operation, claimant, at);
    operation = fixture
        .store
        .compare_and_swap(
            &command(
                &operation,
                recovery,
                vec![AdmissionAttachment::ToolOutcomeId(
                    outcome.outcome_id().clone(),
                )],
                AdmissionOperationState::Finalizing,
                None,
            ),
            at,
        )?
        .into_operation();
    let recovery = claim(fixture, &operation, claimant, at);
    let context = AdmissionProjectionContext {
        operation_id: operation.binding().operation_id().clone(),
        request_id: operation.replay_key().request_id,
        expected_operation_version: operation.version(),
        trusted_time_unix_ms: at,
        coordinator_lease_id: recovery.coordinator_lease_id().clone(),
        coordinator_lease_epoch: recovery.coordinator_lease_epoch(),
        store_fence: recovery.store_fence().clone(),
    };
    let tool_outcome = ToolOutcomeTerminalEvidenceV1::from_records_for_test(
        &operation,
        &context,
        &outcome,
        &evaluation,
    )?;
    let content_hash = outcome
        .resolved_output_ref()
        .ok_or("resolved output is absent")?
        .0
        .digest()
        .clone();
    let metadata = AdmissionReceiptMetadataV1 {
        schema: AdmissionReceiptSchema::V1,
        operation_id: operation.binding().operation_id().clone(),
        request_id: operation.replay_key().request_id,
        request_namespace_digest: operation.binding().request_namespace_digest().clone(),
        request_binding_hash: operation.binding().request_binding_hash().clone(),
        projected_operation_version: operation
            .version()
            .checked_add(1)
            .ok_or("terminal operation version overflow")?,
        projected_state: AdmissionOperationState::Completed,
        projected_dispatch_state: AdmissionDispatchState::Terminal,
        trusted_time_unix_ms: context.trusted_time_unix_ms,
        coordinator_lease_id: context.coordinator_lease_id.clone(),
        coordinator_lease_epoch: context.coordinator_lease_epoch,
        store_fence: context.store_fence.clone(),
        retained_dispatch_commit: operation.dispatch_commit().cloned(),
        compensation_status: AdmissionCompensationStatus::NotCompensated,
        tool_outcome_id: Some(outcome.outcome_id().clone()),
        tool_outcome_version: Some(outcome.version()),
    };
    let kernel = Keypair::from_seed(&[0x71; 32]);
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: format!("per-call-receipt-{suffix}"),
            timestamp: at / 1_000,
            capability_id: operation.binding().capability_id().as_str().to_owned(),
            tool_server: "tool-outcome-test-server".to_owned(),
            tool_name: "tool-outcome-test-tool".to_owned(),
            action,
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: content_hash.as_str().to_owned(),
            policy_hash: operation.binding().policy_hash().as_str().to_owned(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({ ADMISSION_RECEIPT_METADATA_KEY: metadata })),
            trust_level: Default::default(),
            tenant_id: None,
            kernel_key: kernel.public_key(),
            bbs_projection_version: None,
        },
        &kernel,
    )?;
    let receipt = VerifiedAdmissionReceipt::from_kernel_verified_for_test(
        receipt,
        &kernel.public_key(),
        &Decision::Allow,
        "tool-outcome-test-server",
        "tool-outcome-test-tool",
        operation.binding().action_parameter_hash(),
        &content_hash,
        &operation,
        &context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
        Some((outcome.outcome_id(), outcome.version())),
    )?;
    let mut source_body = receipt.receipt().body();
    source_body.id = "shared-source-authorization".into();
    source_body.action = ToolCallAction::from_parameters(serde_json::json!({
        "operation_payload": receipt.receipt().action.parameters,
        "authorization_parameter_hash": operation.binding().action_parameter_hash(),
        "session_id": "authorization-session", "tool_call_id": "authorization-tool-call",
    }))?;
    source_body.metadata = Some(serde_json::json!({"receipt_context": {
        "request_id": operation.binding().request_id(),
        "authorization_capability_hash": operation.binding().authorization_capability_hash(),
    }}));
    let source = ChioReceipt::sign(source_body, &kernel)?;
    let consumption = AuthorizationReceiptConsumption {
        authorization_receipt_id: source.id.clone(),
        consumer_receipt_id: receipt.receipt().id.clone(),
        request_id: operation.binding().request_id().as_str().to_owned(),
        session_id: "authorization-session".to_owned(),
        tool_call_id: "authorization-tool-call".to_owned(),
        tenant_id: None,
        parameter_hash: operation
            .binding()
            .action_parameter_hash()
            .as_str()
            .to_owned(),
        consumed_at_unix_ms: at,
    };
    let authorization = VerifiedAuthorizationReceiptConsumption::from_signed_source(
        &operation,
        &context,
        receipt.receipt(),
        &kernel.public_key(),
        &source,
        consumption,
        outcome.outcome_id().clone(),
        outcome.version(),
    )?;
    let projection =
        AdmissionTerminalProjection::Completed(Box::new(AdmissionCompletedProjection {
            context,
            receipt,
            tool_outcome: Some(tool_outcome),
            authorization: Some(authorization),
            payment_evidence: None,
            eligibility: None,
            observer_work: None,
            obligation: None,
            channel_terminal: None,
        }));
    let envelope = SignedAdmissionTerminalProjectionV1::from_verified(
        &operation,
        &projection,
        &fixture.store.admission_projection_capabilities(),
        &kernel,
    )?;
    envelope.verify()?;
    Ok(Candidate {
        operation,
        envelope,
    })
}

fn terminal_counts(fixture: &Fixture) -> AnchoredTestResult<(i64, i64, i64)> {
    Ok(fixture.store.connection()?.query_row(
        "SELECT
        (SELECT COUNT(*) FROM admission_operation_terminal_projections),
        (SELECT COUNT(*) FROM admission_operation_authorization_consumptions),
        (SELECT COUNT(*) FROM admission_operation_commits)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?)
}

// Resign the entire adversarial envelope, including the modified canonical
// records and manifest. Each negative must reach semantic binding validation.
fn substituted(
    candidate: &Candidate,
    variant: usize,
) -> AnchoredTestResult<SignedAdmissionTerminalProjectionV1> {
    let mut wire = serde_json::to_value(&candidate.envelope)?;
    let body = &mut wire["body"];
    let mut projection: serde_json::Value = serde_json::from_slice(
        &STANDARD.decode(body["projection_json"].as_str().ok_or("projection")?)?,
    )?;
    let mut manifest: serde_json::Value = serde_json::from_slice(
        &STANDARD.decode(body["manifest_json"].as_str().ok_or("manifest")?)?,
    )?;
    let records = body["records"].as_array_mut().ok_or("records")?;
    let record = records
        .iter_mut()
        .find(|record| record["kind"] == "authorization_consumption")
        .ok_or("authorization record")?;
    let mut proof: serde_json::Value = serde_json::from_slice(
        &STANDARD.decode(record["canonical_json"].as_str().ok_or("record")?)?,
    )?;
    match variant {
        0 => proof["consumption"]["tenantId"] = "foreign-tenant".into(),
        1 => proof["consumption"]["requestId"] = "foreign-request".into(),
        2 => proof["consumption"]["consumerReceiptId"] = "foreign-consumer".into(),
        3 => proof["consumption"]["parameterHash"] = "d".repeat(64).into(),
        4 => proof["outcome_id"] = "e".repeat(64).into(),
        5 => proof["outcome_version"] = 7.into(),
        6 => {
            let source: ChioReceipt = serde_json::from_value(proof["source_receipt"].clone())?;
            let mut body = source.body();
            body.tenant_id = Some("foreign-source-tenant".to_owned());
            let changed = ChioReceipt::sign(body, &signer())?;
            proof["source_receipt_digest"] = sha256_hex(&canonical_json_bytes(&changed)?).into();
            proof["consumption"]["authorizationReceiptId"] = changed.id.clone().into();
            proof["source_receipt"] = serde_json::to_value(changed)?;
        }
        7 => proof["consumption"]["authorizationReceiptId"] = "foreign-source".into(),
        _ => return Err("unknown substitution".into()),
    }
    projection["authorization"] = proof.clone();
    record["record_id"] = proof["consumption"]["authorizationReceiptId"].clone();
    let bytes = canonical_json_bytes(&proof)?;
    record["record_digest"] = sha256_hex(&bytes).into();
    record["canonical_json"] = STANDARD.encode(bytes).into();
    let commitment = manifest["records"]
        .as_array_mut()
        .ok_or("manifest records")?
        .iter_mut()
        .find(|record| record["kind"] == "authorization_consumption")
        .ok_or("manifest authorization")?;
    commitment["record_id"] = record["record_id"].clone();
    commitment["record_digest"] = record["record_digest"].clone();
    body["authorization_consumption"] = proof["consumption"].clone();
    let projection_bytes = canonical_json_bytes(&projection)?;
    manifest["projection_body_digest"] = sha256_hex(&projection_bytes).into();
    let manifest_bytes = canonical_json_bytes(&manifest)?;
    *body
        .pointer_mut("/terminal_operation/terminal_replay/receipt/projection_digest")
        .ok_or("receipt replay digest")? = sha256_hex(&manifest_bytes).into();
    body["projection_json"] = STANDARD.encode(projection_bytes).into();
    body["manifest_json"] = STANDARD.encode(manifest_bytes).into();
    let mut preimage = b"chio.signed-admission-terminal-projection.v1\0".to_vec();
    preimage.extend(canonical_json_bytes(body)?);
    wire["signature"] = serde_json::to_value(signer().sign(&preimage))?;
    Ok(serde_json::from_value(wire)?)
}

#[test]
fn signed_authorization_consumption_rejects_substitutions_and_reopens_exactly() -> AnchoredTestResult
{
    let fixture = fixture();
    let candidate = candidate(&fixture, "primary", now_ms(), &claimant())?;
    let before = terminal_counts(&fixture)?;
    for variant in 0..8 {
        let altered = substituted(&candidate, variant)?;
        assert!(matches!(altered.verify(), Err(chio_kernel::admission_operation::AdmissionOperationError::TerminalProjectionBindingMismatch)), "variant {variant}");
        assert!(
            matches!(
                fixture.store.commit_signed_terminal_projection(&altered),
                Err(AdmissionOperationStoreError::Operation(
                    chio_kernel::admission_operation::AdmissionOperationError::TerminalProjectionBindingMismatch
                ))
            ),
            "variant {variant}"
        );
        assert_eq!(terminal_counts(&fixture)?, before);
        assert_eq!(
            fixture
                .store
                .load_by_operation_id(candidate.operation.binding().operation_id())?,
            Some(candidate.operation.clone())
        );
    }
    let verified = candidate.envelope.verify()?;
    let first = fixture
        .store
        .commit_signed_terminal_projection(&candidate.envelope)?;
    let committed = terminal_counts(&fixture)?;
    assert_eq!((committed.0, committed.1), (1, 1));
    assert_eq!(
        fixture
            .store
            .commit_signed_terminal_projection(&candidate.envelope)?,
        first
    );
    assert_eq!(terminal_counts(&fixture)?, committed);
    // A signed but altered replay cannot replace an already committed terminal.
    assert!(matches!(fixture.store.commit_signed_terminal_projection(&substituted(&candidate, 0)?),
        Err(AdmissionOperationStoreError::Operation(
            chio_kernel::admission_operation::AdmissionOperationError::TerminalProjectionBindingMismatch))));
    assert_eq!(terminal_counts(&fixture)?, committed);
    let original_bytes = verified.projection_json().to_vec();
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        ..
    } = fixture;
    drop(store);
    drop(authority);
    let reopened = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let store = reopened.admission_operation_store();
    let replay = store
        .load_terminal_replay(&candidate.operation.replay_key())?
        .ok_or("terminal replay")?;
    assert_eq!(replay, first.replay);
    let retained_bytes: Vec<u8> = Connection::open(&database)?.query_row(
        "SELECT projection_json FROM admission_operation_terminal_projections WHERE operation_id = ?1",
        [candidate.operation.binding().operation_id().as_str()], |row| row.get(0))?;
    assert_eq!(retained_bytes, original_bytes);
    let connection = store.connection()?;
    let tamper =
        "UPDATE admission_operation_authorization_consumptions SET tenant_id = 'foreign-tenant'";
    assert!(
        matches!(connection.execute(tamper, []), Err(rusqlite::Error::SqliteFailure(_, Some(message)))
        if message == "admission authorization consumption is immutable")
    );
    // Negative fixture only: use the owner's connection and restore the exact
    // catalog so readback must reject the row binding independently of external
    // write detection and missing schema guards.
    let guard: String = connection.query_row(
        "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'admission_operation_authorization_consumptions_immutable'",
        [], |row| row.get(0))?;
    connection
        .execute_batch("DROP TRIGGER admission_operation_authorization_consumptions_immutable")?;
    connection.execute(tamper, [])?;
    connection.execute_batch(&guard)?;
    drop(connection);
    let corrupted = store.load_terminal_replay(&candidate.operation.replay_key());
    assert!(
        matches!(&corrupted, Err(AdmissionOperationStoreError::Invariant(message)) if message.contains("authorization consumption projection is inconsistent")),
        "unexpected corruption result: {corrupted:?}"
    );
    Ok(())
}

#[test]
fn authorization_consumption_refuses_other_claimants_and_double_consumption_atomically(
) -> AnchoredTestResult {
    let fixture = fixture();
    let at = now_ms();
    let first = candidate(&fixture, "first", at, &claimant())?;
    fixture
        .store
        .commit_signed_terminal_projection(&first.envelope)?;
    let second = candidate(&fixture, "second", at, &claimant())?;
    assert_eq!(
        first
            .envelope
            .verify()?
            .authorization_consumption()
            .ok_or("first")?
            .authorization_receipt_id,
        second
            .envelope
            .verify()?
            .authorization_consumption()
            .ok_or("second")?
            .authorization_receipt_id
    );
    let before = terminal_counts(&fixture)?;
    assert!(
        matches!(fixture.store.commit_signed_terminal_projection(&second.envelope), Err(AdmissionOperationStoreError::Unavailable(message)) if message.contains("UNIQUE constraint failed"))
    );
    assert_eq!(terminal_counts(&fixture)?, before);
    assert_eq!(
        fixture
            .store
            .load_by_operation_id(second.operation.binding().operation_id())?,
        Some(second.operation)
    );
    let other = candidate(
        &fixture,
        "foreign-claimant",
        now_ms(),
        "kernel:foreign-claimant",
    )?;
    let before = terminal_counts(&fixture)?;
    assert!(matches!(
        fixture
            .store
            .commit_signed_terminal_projection(&other.envelope),
        Err(AdmissionOperationStoreError::Fenced)
    ));
    assert_eq!(terminal_counts(&fixture)?, before);
    Ok(())
}
