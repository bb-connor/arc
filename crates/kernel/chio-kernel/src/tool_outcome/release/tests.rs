use super::*;
use crate::dispatch_status::{
    qualify_dispatch_status_provider_for_test, resolve_dispatch_status,
    AuthenticatedProviderAcceptance, AuthenticatedProviderCompletedOutcome,
    AuthenticatedProviderNotAccepted, DispatchStatusProvider, DispatchStatusProviderError,
    ProviderDispatchStatusObservation, QualifiedDispatchStatusProvider, VerifiedDispatchStatus,
    VerifiedProviderNotAccepted,
};
use crate::tool_outcome::tests::{
    admission_digest, advance, committed_broker_operation, committed_operation, id,
    prepared_operation, projection_context, projection_context_under, provider_attempt, resolve,
    returned, successor_fence,
};
use chio_core_types::provider_attempt::{
    ProviderAcceptanceBindingV1, ProviderAttemptPhaseV1, ProviderCancellationBindingV1,
    ProviderCompletionBindingV1, ProviderInvocationBlobBindingV1,
    PROVIDER_ATTEMPT_CHECKPOINT_SCHEMA, PROVIDER_CANCELLATION_SCHEMA,
    PROVIDER_INVOCATION_BLOB_SCHEMA,
};
use std::sync::Arc;

fn query_record(
    name: &str,
    attachments: Vec<AdmissionAttachment>,
    observed_at_unix_ms: u64,
) -> ParticipantQueryRecordV1 {
    ParticipantQueryRecordV1::for_test(
        id(&format!("{name}-record")),
        admission_digest(name),
        attachments,
        observed_at_unix_ms,
    )
}

fn not_dispatched(operation: &AdmissionOperationV1) -> VerifiedParticipantNoEffectV1 {
    VerifiedParticipantNoEffectV1::not_dispatched(
        operation,
        query_record("transport-not-dispatched", Vec::new(), 1_000),
    )
    .unwrap()
}

fn no_effect_dispositions(
    operation: &AdmissionOperationV1,
) -> PreDispatchParticipantDispositionsV1 {
    let broker = match operation.provider_attempt() {
        Some(attempt) => VerifiedParticipantNoEffectV1::released_before_dispatch(
            operation,
            ReleaseParticipantV1::Broker,
            query_record(
                "broker-released",
                vec![AdmissionAttachment::BrokerAttempt(attempt.clone())],
                1_000,
            ),
        )
        .unwrap(),
        None => VerifiedParticipantNoEffectV1::never_acquired(
            operation,
            ReleaseParticipantV1::Broker,
            query_record("broker-never-acquired", Vec::new(), 1_000),
        )
        .unwrap(),
    };
    PreDispatchParticipantDispositionsV1::from_verified_parts(
        broker,
        VerifiedParticipantNoEffectV1::never_acquired(
            operation,
            ReleaseParticipantV1::Budget,
            query_record("budget-never-acquired", Vec::new(), 1_000),
        )
        .unwrap(),
        VerifiedParticipantNoEffectV1::NotRequired,
        VerifiedParticipantNoEffectV1::NotRequired,
        VerifiedParticipantNoEffectV1::NotRequired,
        VerifiedParticipantNoEffectV1::NotRequired,
        not_dispatched(operation),
    )
}

fn predispatch_proof(
    operation: &AdmissionOperationV1,
    context: &AdmissionProjectionContext,
) -> VerifiedPreDispatchNoEffect {
    VerifiedPreDispatchNoEffect::from_verified_snapshot(
        operation,
        context,
        no_effect_dispositions(operation),
        serde_json::json!({"policy": "release-v1"}),
    )
    .unwrap()
}

fn predispatch_bundle() -> (
    AdmissionOperationV1,
    AdmissionProjectionContext,
    MonetaryReleaseEvidenceV1,
) {
    let operation = prepared_operation("request-release");
    let context = projection_context(&operation);
    let proof = predispatch_proof(&operation, &context);
    let bundle = MonetaryReleaseAuthority::NoEffect(VerifiedNoEffectProof::BeforeDispatch(proof))
        .evidence_bundle()
        .unwrap();
    (operation, context, bundle)
}

#[test]
fn release_evidence_has_one_owned_canonical_encoding() {
    let (_, _, bundle) = predispatch_bundle();
    let bytes = bundle.canonical_bytes().unwrap();
    assert_eq!(
        MonetaryReleaseEvidenceV1::from_canonical_bytes(&bytes).unwrap(),
        bundle
    );

    let mut unknown_schema = bundle.to_persisted();
    unknown_schema.schema = "chio.monetary-release-evidence.v2".to_owned();
    assert!(
        MonetaryReleaseEvidenceV1::from_canonical_bytes(&canonical(&unknown_schema).unwrap())
            .is_err()
    );

    let mut unknown_field = serde_json::to_value(bundle.to_persisted()).unwrap();
    unknown_field
        .as_object_mut()
        .unwrap()
        .insert("unknown".to_owned(), Value::Bool(true));
    assert!(
        MonetaryReleaseEvidenceV1::from_canonical_bytes(&canonical(&unknown_field).unwrap())
            .is_err()
    );

    let mut unknown_source = bundle.to_persisted();
    let source_bytes = BASE64
        .decode(&unknown_source.source_binding_base64)
        .unwrap();
    let mut source: Value = serde_json::from_slice(&source_bytes).unwrap();
    source
        .as_object_mut()
        .unwrap()
        .insert("unknown".to_owned(), Value::Bool(true));
    let source_bytes = canonical(&source).unwrap();
    unknown_source.source_binding_base64 = BASE64.encode(&source_bytes);
    unknown_source.source_binding_digest =
        digest_bytes("test_source_binding", &source_bytes).unwrap();
    assert!(MonetaryReleaseEvidenceV1::from_persisted(unknown_source).is_err());

    let mut noncanonical = vec![b' '];
    noncanonical.extend_from_slice(&bytes);
    assert!(MonetaryReleaseEvidenceV1::from_canonical_bytes(&noncanonical).is_err());
    assert!(matches!(
        MonetaryReleaseEvidenceV1::from_canonical_bytes(&vec![
            b' ';
            MAX_MONETARY_RELEASE_EVIDENCE_BYTES
                + 1
        ]),
        Err(ToolOutcomeError::TooLarge { .. })
    ));
}

#[test]
fn release_evidence_kinds_and_artifacts_cannot_be_substituted() {
    let (_, _, bundle) = predispatch_bundle();
    let mut wrong_kind = bundle.clone();
    wrong_kind.evidence_kind = MonetaryReleaseEvidenceKindV1::NotAcceptedAfterDispatch;
    assert!(wrong_kind.validate().is_err());

    let mut changed_artifact = bundle;
    changed_artifact.source_artifacts[0].value = serde_json::json!({"substituted": true});
    assert!(changed_artifact.validate().is_err());
}

#[test]
fn persisted_release_recovery_enforces_fence_time_and_coordinator_lineage() {
    let (operation, context, bundle) = predispatch_bundle();
    bundle
        .validate_recovery_context(&operation, &context)
        .unwrap();

    let mut successor = projection_context_under(&operation, successor_fence(10));
    successor.coordinator_lease_id = id("coordinator-lease-2");
    successor.trusted_time_unix_ms = 1_100;
    bundle
        .validate_recovery_context(&operation, &successor)
        .unwrap();

    let mut lower = projection_context_under(&operation, successor_fence(8));
    lower.trusted_time_unix_ms = 1_100;
    assert!(bundle
        .validate_recovery_context(&operation, &lower)
        .is_err());

    let mut cross_store = successor.clone();
    cross_store.store_fence.store_uuid = "other-store".to_owned();
    assert!(bundle
        .validate_recovery_context(&operation, &cross_store)
        .is_err());

    let mut same_epoch_new_store_lease = context.clone();
    same_epoch_new_store_lease.store_fence.lease_id = "other-store-lease".to_owned();
    assert!(bundle
        .validate_recovery_context(&operation, &same_epoch_new_store_lease)
        .is_err());

    let mut same_fence_new_coordinator = context.clone();
    same_fence_new_coordinator.coordinator_lease_id = id("coordinator-lease-other");
    assert!(bundle
        .validate_recovery_context(&operation, &same_fence_new_coordinator)
        .is_err());

    let mut rolled_back_time = context.clone();
    rolled_back_time.trusted_time_unix_ms = 999;
    assert!(bundle
        .validate_recovery_context(&operation, &rolled_back_time)
        .is_err());

    let substituted_epoch = bundle
        .with_projection_epoch_for_test(context.coordinator_lease_epoch + 1)
        .unwrap();
    assert!(substituted_epoch
        .validate_recovery_context(&operation, &context)
        .is_err());
    let substituted_request = bundle
        .with_request_binding_hash_for_test(admission_digest("other-request-binding"))
        .unwrap();
    assert!(substituted_request
        .validate_recovery_context(&operation, &context)
        .is_err());

    assert!(matches!(
        bundle.revalidate_authority(&operation, &context),
        Err(ToolOutcomeError::ReleaseAuthorityUnavailable(_))
    ));
}

#[test]
fn predispatch_manifest_binds_required_participants_and_exact_attachments() {
    let prepared = prepared_operation("request-release-participants");
    let context = projection_context(&prepared);

    let mut extra_attachment = no_effect_dispositions(&prepared);
    extra_attachment.budget = VerifiedParticipantNoEffectV1::never_acquired(
        &prepared,
        ReleaseParticipantV1::Budget,
        query_record(
            "budget-extra",
            vec![AdmissionAttachment::BudgetHoldId(id("unbound-hold"))],
            1_000,
        ),
    )
    .unwrap();
    assert!(VerifiedPreDispatchNoEffect::from_verified_snapshot(
        &prepared,
        &context,
        extra_attachment,
        serde_json::json!({"policy": "release-v1"}),
    )
    .is_err());

    let broker = advance(
        &prepared,
        AdmissionOperationState::BrokerAttemptRegistered,
        vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
            &prepared,
            "attempt-release",
        ))],
    );
    let budget = advance(
        &broker,
        AdmissionOperationState::BudgetAuthorized,
        vec![AdmissionAttachment::BudgetHoldId(id("hold-release"))],
    );
    let budget_context = projection_context(&budget);
    let released = |attachments| {
        VerifiedParticipantNoEffectV1::released_before_dispatch(
            &budget,
            ReleaseParticipantV1::Budget,
            query_record("budget-released", attachments, 1_000),
        )
        .unwrap()
    };
    let dispositions = |budget_disposition| {
        PreDispatchParticipantDispositionsV1::from_verified_parts(
            no_effect_dispositions(&budget).broker,
            budget_disposition,
            VerifiedParticipantNoEffectV1::NotRequired,
            VerifiedParticipantNoEffectV1::NotRequired,
            VerifiedParticipantNoEffectV1::NotRequired,
            VerifiedParticipantNoEffectV1::NotRequired,
            not_dispatched(&budget),
        )
    };

    assert!(VerifiedPreDispatchNoEffect::from_verified_snapshot(
        &budget,
        &budget_context,
        dispositions(released(Vec::new())),
        serde_json::json!({"policy": "release-v1"}),
    )
    .is_err());
    assert!(VerifiedPreDispatchNoEffect::from_verified_snapshot(
        &budget,
        &budget_context,
        dispositions(released(vec![AdmissionAttachment::BrokerAttempt(
            provider_attempt(&budget, "wrong-slot"),
        )])),
        serde_json::json!({"policy": "release-v1"}),
    )
    .is_err());

    let proof = VerifiedPreDispatchNoEffect::from_verified_snapshot(
        &budget,
        &budget_context,
        dispositions(released(vec![AdmissionAttachment::BudgetHoldId(id(
            "hold-release",
        ))])),
        serde_json::json!({"policy": "release-v1"}),
    )
    .unwrap();
    let mut missing_required = proof.clone();
    missing_required
        .snapshot
        .participant_manifest
        .required_participants
        .retain(|participant| *participant != ReleaseParticipantV1::Transport);
    assert!(missing_required
        .validate_against(&budget, &budget_context)
        .is_err());

    let mut extra_required = proof;
    extra_required
        .snapshot
        .participant_manifest
        .required_participants
        .push(ReleaseParticipantV1::Payment);
    assert!(extra_required
        .validate_against(&budget, &budget_context)
        .is_err());
}

#[test]
fn predispatch_release_rejects_evidence_and_future_time_substitution() {
    let prepared = prepared_operation("request-release-substitution");
    let mut budget_evidence = VerifiedParticipantNoEffectV1::never_acquired(
        &prepared,
        ReleaseParticipantV1::Budget,
        query_record("budget-tampered", Vec::new(), 1_000),
    )
    .unwrap();
    let VerifiedParticipantNoEffectV1::NeverAcquired { evidence } = &mut budget_evidence else {
        unreachable!();
    };
    evidence.evidence_digest = admission_digest("tampered-participant-evidence");
    let dispositions = PreDispatchParticipantDispositionsV1::from_verified_parts(
        VerifiedParticipantNoEffectV1::NotRequired,
        budget_evidence,
        VerifiedParticipantNoEffectV1::NotRequired,
        VerifiedParticipantNoEffectV1::NotRequired,
        VerifiedParticipantNoEffectV1::NotRequired,
        VerifiedParticipantNoEffectV1::NotRequired,
        not_dispatched(&prepared),
    );
    assert!(VerifiedPreDispatchNoEffect::from_verified_snapshot(
        &prepared,
        &projection_context(&prepared),
        dispositions,
        serde_json::json!({"policy": "release-v1"}),
    )
    .is_err());

    let mut future = no_effect_dispositions(&prepared);
    future.budget = VerifiedParticipantNoEffectV1::never_acquired(
        &prepared,
        ReleaseParticipantV1::Budget,
        query_record("budget-future", Vec::new(), 1_001),
    )
    .unwrap();
    assert!(VerifiedPreDispatchNoEffect::from_verified_snapshot(
        &prepared,
        &projection_context(&prepared),
        future,
        serde_json::json!({"policy": "release-v1"}),
    )
    .is_err());
}

#[test]
fn contractual_zero_charge_requires_exact_typed_terminal_records() {
    let operation = committed_operation("request-zero");
    let returned_record = returned(&operation, serde_json::json!(1));
    let (zero_outcome, zero_evaluation) = resolve(
        &operation,
        &returned_record,
        SettlementDispositionV1::ContractualZeroCharge {
            currency: "USD".to_owned(),
        },
    );
    let context = projection_context(&operation);
    let proof = VerifiedContractualZeroCharge::from_records(
        &operation,
        &context,
        &zero_outcome,
        &zero_evaluation,
    )
    .unwrap();
    let authority = MonetaryReleaseAuthority::ContractualZeroCharge(Box::new(proof));
    let bundle = authority.evidence_bundle().unwrap();
    MonetaryReleaseEvidenceV1::from_canonical_bytes(&bundle.canonical_bytes().unwrap()).unwrap();

    let mut substituted = bundle.clone();
    substituted.source_artifacts[0].value["request_id"] = Value::String("other-request".to_owned());
    substituted.source_artifacts[0].digest = digest_bytes(
        "substituted_artifact",
        &bounded(
            "substituted_artifact",
            &substituted.source_artifacts[0].value,
            MAX_EVIDENCE_ARTIFACT_BYTES,
        )
        .unwrap(),
    )
    .unwrap();
    assert!(substituted.validate().is_err());

    let (capture_outcome, capture_evaluation) = resolve(
        &operation,
        &returned_record,
        SettlementDispositionV1::Capture {
            amount: MonetaryAmount {
                units: 1,
                currency: "USD".to_owned(),
            },
        },
    );
    assert!(VerifiedContractualZeroCharge::from_records(
        &operation,
        &context,
        &capture_outcome,
        &capture_evaluation,
    )
    .is_err());

    let other_operation = committed_operation("request-other");
    let other = returned(&other_operation, serde_json::json!(1));
    let (other_outcome, _) = resolve(
        &other_operation,
        &other,
        SettlementDispositionV1::NotApplicable,
    );
    assert!(VerifiedContractualZeroCharge::from_records(
        &operation,
        &context,
        &other_outcome,
        &zero_evaluation,
    )
    .is_err());
}

#[derive(Clone)]
struct ReleaseStatusProvider {
    checkpoints: Vec<ProviderAttemptCheckpointV1>,
    cancellation: ProviderCancellationBindingV1,
}

impl DispatchStatusProvider for ReleaseStatusProvider {
    fn transport_id(&self) -> &str {
        "qualified-release-provider"
    }

    fn transport_key_epoch(&self) -> u64 {
        7
    }

    fn status(
        &self,
        _query: &DispatchStatusQuery,
    ) -> Result<ProviderDispatchStatusObservation, DispatchStatusProviderError> {
        Ok(ProviderDispatchStatusObservation::Checkpoints(
            self.checkpoints.clone(),
        ))
    }

    fn fetch_acceptance(
        &self,
        _binding: &ProviderAcceptanceBindingV1,
    ) -> Result<AuthenticatedProviderAcceptance, DispatchStatusProviderError> {
        Err(DispatchStatusProviderError::new("unused acceptance"))
    }

    fn fetch_not_accepted(
        &self,
        _binding: &ProviderCancellationBindingV1,
    ) -> Result<AuthenticatedProviderNotAccepted, DispatchStatusProviderError> {
        Ok(AuthenticatedProviderNotAccepted {
            binding: self.cancellation.clone(),
            proof: b"cancelled".to_vec(),
        })
    }

    fn fetch_completed_outcome(
        &self,
        _binding: &ProviderCompletionBindingV1,
    ) -> Result<AuthenticatedProviderCompletedOutcome, DispatchStatusProviderError> {
        Err(DispatchStatusProviderError::new("unused completion"))
    }
}

fn verified_not_accepted_case(
    operation: &AdmissionOperationV1,
    attempt_id: &str,
    continuity_anchor: &str,
) -> (
    QualifiedDispatchStatusProvider,
    DispatchStatusQuery,
    VerifiedProviderNotAccepted,
) {
    let attempt = operation
        .provider_attempt()
        .filter(|attempt| attempt.attempt_id == attempt_id)
        .cloned()
        .expect("test operation must bind the requested provider attempt");
    let blob = ProviderInvocationBlobBindingV1 {
        schema: PROVIDER_INVOCATION_BLOB_SCHEMA.to_owned(),
        attempt: attempt.clone(),
        request_digest: operation
            .binding()
            .request_binding_hash()
            .as_str()
            .to_owned(),
        idempotency_key: attempt.operation_id.clone(),
        blob_ref: format!("cas://release-invocation/{attempt_id}"),
        blob_sha256: sha256_hex(b"release-invocation"),
        blob_size_bytes: 18,
        availability_ref: format!("anchor://release-invocation/{attempt_id}"),
        availability_sha256: sha256_hex(b"release-availability"),
    };
    let cancellation = ProviderCancellationBindingV1 {
        schema: PROVIDER_CANCELLATION_SCHEMA.to_owned(),
        attempt: attempt.clone(),
        cancellation_ref: format!("provider://release-cancelled/{attempt_id}"),
        cancelled_at: 900,
        cancellation_fence: 4,
        invocation_blob_digest: blob.digest().unwrap(),
        no_acceptance_proof_sha256: sha256_hex(b"cancelled"),
        no_acceptance_proof_size_bytes: 9,
    };
    let pending = ProviderAttemptCheckpointV1 {
        schema: PROVIDER_ATTEMPT_CHECKPOINT_SCHEMA.to_owned(),
        attempt: attempt.clone(),
        checkpoint_sequence: 1,
        previous_checkpoint_digest: None,
        phase: ProviderAttemptPhaseV1::Pending {
            invocation_blob: blob.clone(),
        },
    };
    let cancelled = ProviderAttemptCheckpointV1 {
        schema: PROVIDER_ATTEMPT_CHECKPOINT_SCHEMA.to_owned(),
        attempt: attempt.clone(),
        checkpoint_sequence: 2,
        previous_checkpoint_digest: Some(pending.digest().unwrap()),
        phase: ProviderAttemptPhaseV1::Cancelled {
            invocation_blob: blob,
            cancellation: cancellation.clone(),
        },
    };
    let qualification = qualify_dispatch_status_provider_for_test(
        Arc::new(ReleaseStatusProvider {
            checkpoints: vec![pending, cancelled],
            cancellation,
        }),
        "release-ed25519-verifier",
        continuity_anchor,
        11,
        "chio.release-provider-status.v1",
    )
    .unwrap();
    let query = DispatchStatusQuery {
        attempt,
        last_checkpoint: None,
        observed_at: 950,
    };
    let VerifiedDispatchStatus::NotAccepted(status) =
        resolve_dispatch_status(Some(&qualification), &query).unwrap()
    else {
        panic!("test provider must return verified non-acceptance");
    };
    (qualification, query, status)
}

#[test]
fn transport_release_rejects_same_attempt_cancellation_substitution() {
    let operation = committed_broker_operation("request-transport-release", "attempt-release");
    let (first, query, status) =
        verified_not_accepted_case(&operation, "attempt-release", "continuity-anchor-a");
    let (second, _, _) =
        verified_not_accepted_case(&operation, "attempt-release", "continuity-anchor-b");
    let context = projection_context(&operation);
    let commit = operation.dispatch_commit().unwrap();
    let proof = VerifiedTransportNotAccepted::from_verified_provider(
        &status,
        &first,
        &query,
        &operation,
        commit,
        &context,
        id("release-verifier"),
        serde_json::json!({"policy": "transport-release-v1"}),
    )
    .unwrap();
    let bundle = MonetaryReleaseAuthority::NoEffect(
        VerifiedNoEffectProof::NotAcceptedAfterDispatch(Box::new(proof)),
    )
    .evidence_bundle()
    .unwrap();
    MonetaryReleaseEvidenceV1::from_persisted(bundle.to_persisted()).unwrap();

    let mut substituted_cancellation = status.cancellation().clone();
    substituted_cancellation.cancellation_ref =
        "provider://same-attempt-substituted-cancellation".to_owned();
    let substituted_status = status.with_cancellation_for_test(substituted_cancellation.clone());
    assert!(VerifiedTransportNotAccepted::from_verified_provider(
        &substituted_status,
        &first,
        &query,
        &operation,
        commit,
        &context,
        id("release-verifier"),
        serde_json::json!({"policy": "transport-release-v1"}),
    )
    .is_err());

    let mut persisted = bundle.to_persisted();
    let checkpoint = persisted.source_artifacts[1].clone();
    persisted.source_artifacts[0].evidence_id = id(&substituted_cancellation.cancellation_ref);
    persisted.source_artifacts[0].value["cancellation"] =
        serde_json::to_value(&substituted_cancellation).unwrap();
    persisted.source_artifacts[0].digest = digest_bytes(
        "release_artifact.digest",
        &bounded(
            "release_artifact.value",
            &persisted.source_artifacts[0].value,
            MAX_EVIDENCE_ARTIFACT_BYTES,
        )
        .unwrap(),
    )
    .unwrap();

    let cancellation_digest = imported_digest(
        "transport_release.signed_status_digest",
        substituted_cancellation.digest().unwrap(),
    )
    .unwrap();
    let source_bytes = BASE64.decode(&persisted.source_binding_base64).unwrap();
    let mut source: Value = serde_json::from_slice(&source_bytes).unwrap();
    source["binding"]["signed_status_digest"] = serde_json::to_value(cancellation_digest).unwrap();
    let source_bytes = canonical(&source).unwrap();
    persisted.source_binding_base64 = BASE64.encode(&source_bytes);
    persisted.source_binding_digest =
        digest_bytes("release.source_binding_digest", &source_bytes).unwrap();

    let body = serde_json::json!({
        "schema": persisted.schema,
        "evidence_kind": persisted.evidence_kind,
        "operation_id": persisted.operation_id,
        "operation_version": persisted.operation_version,
        "verifier_policy_digest": persisted.verifier_policy_digest,
        "source_binding_base64": persisted.source_binding_base64,
        "source_binding_digest": persisted.source_binding_digest,
        "source_artifacts": persisted.source_artifacts,
    });
    persisted.evidence_id =
        domain_digest("chio.monetary-release-evidence.identity.v1", &body).unwrap();
    persisted.bundle_digest = digest_bytes(
        "release.bundle_digest",
        &bounded(
            "monetary_release_evidence",
            &body,
            MAX_MONETARY_RELEASE_EVIDENCE_BYTES,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(persisted.source_artifacts[1], checkpoint);
    assert_eq!(
        MonetaryReleaseEvidenceV1::from_persisted(persisted).unwrap_err(),
        ToolOutcomeError::Binding("transport_release.artifacts")
    );

    assert!(VerifiedTransportNotAccepted::from_verified_provider(
        &status,
        &second,
        &query,
        &operation,
        commit,
        &context,
        id("release-verifier"),
        serde_json::json!({"policy": "transport-release-v1"}),
    )
    .is_err());
}

#[test]
fn transport_release_binds_registered_broker_attempt() {
    let operation = committed_broker_operation("request-transport-broker", "attempt-release");
    let sibling = committed_broker_operation("request-transport-broker", "attempt-sibling");
    assert_eq!(
        operation.binding().operation_id(),
        sibling.binding().operation_id()
    );
    assert_eq!(operation.replay_key(), sibling.replay_key());
    assert_ne!(operation.dispatch_commit(), sibling.dispatch_commit());

    let context = projection_context(&operation);
    let commit = operation.dispatch_commit().unwrap();
    let (qualification, query, status) =
        verified_not_accepted_case(&operation, "attempt-release", "continuity-anchor-target");
    let proof = VerifiedTransportNotAccepted::from_verified_provider(
        &status,
        &qualification,
        &query,
        &operation,
        commit,
        &context,
        id("release-verifier"),
        serde_json::json!({"policy": "transport-release-v1"}),
    )
    .unwrap();
    proof.validate_against(&operation, &context).unwrap();

    let sibling_context = projection_context(&sibling);
    let sibling_commit = sibling.dispatch_commit().unwrap();
    let (sibling_qualification, sibling_query, sibling_status) =
        verified_not_accepted_case(&sibling, "attempt-sibling", "continuity-anchor-sibling");
    assert_eq!(
        VerifiedTransportNotAccepted::from_verified_provider(
            &sibling_status,
            &sibling_qualification,
            &sibling_query,
            &operation,
            commit,
            &context,
            id("release-verifier"),
            serde_json::json!({"policy": "transport-release-v1"}),
        )
        .unwrap_err(),
        ToolOutcomeError::Binding("transport_not_accepted.provider")
    );

    let sibling_proof = VerifiedTransportNotAccepted::from_verified_provider(
        &sibling_status,
        &sibling_qualification,
        &sibling_query,
        &sibling,
        sibling_commit,
        &sibling_context,
        id("release-verifier"),
        serde_json::json!({"policy": "transport-release-v1"}),
    )
    .unwrap();
    assert_eq!(
        sibling_proof
            .validate_against(&operation, &context)
            .unwrap_err(),
        ToolOutcomeError::Binding("transport_not_accepted.artifacts")
    );
}
