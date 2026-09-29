
    pub(super) use super::{
        build_attested_finding_batch_publication, governed_approval_request_from_native,
        AttestedFindingAdmissionArtifactPayload, AttestedFindingAdmissionArtifacts,
        AttestedFindingBatchPlanner, AttestedFindingDispatchCommittedResume,
        AttestedFindingPreDispatchReconstruction, AttestedFindingResponseCompletionProof,
        AttestedFindingResponseCoordinator, AttestedFindingResponsePolicyPlanner,
        AttestedFindingResponsePolicySelection, AttestedFindingResponseRecoveryLimits,
        CorrelationAttestor, CorrelationPort, DurableAttestedFindingBatchPlanner,
        DurableCorrelationIngress, KernelActiveResponseApprovalVerifier,
        KernelAttestedFindingResponseCoordinator, NativeSecurityEventVerifier,
        PreparedAttestedFindingResponse, ProductionCorrelationConsumer,
        ReservedAttestedFindingResponsePlan, RuleCorrelationOutcome,
        SecurityEventReceiptProjection, SqliteTemporalCorrelationPort,
        TrustedSecurityEventProducer, TrustedSecurityEventReceiptProducer,
        VerifiedSecurityEventIngress, SECURITY_EVENT_RECEIPT_PROJECTION_VERSION,
    };
    pub(super) use crate::security::{DurableActiveResponseExecutor, NativeSecurityReceiptSink};
    pub(super) use chio_core::capability::governance::{
        GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
        GovernedResponseEffect, GovernedResponsePlanIntentBody, GovernedTransactionIntent,
        CHIO_ACTIVE_RESPONSE_SERVER_ID, CHIO_RESPONSE_PLAN_SCHEMA,
    };
    pub(super) use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
    pub(super) use chio_core::capability::threshold_approval::ThresholdApproverIdentity;
    pub(super) use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
    pub(super) use chio_core::{canonical_json_bytes, Ed25519Backend, Keypair};
    pub(super) use chio_core_types::receipt::body::{ChioReceipt, ChioReceiptBody};
    pub(super) use chio_core_types::receipt::decision::ToolCallAction;
    pub(super) use chio_core_types::receipt::kinds::{
        BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
    };
    pub(super) use chio_core_types::receipt::security::{
        ActiveDefenseReceiptBody, CorrelatedFindingReceiptBody,
    };
    pub(super) use chio_core_types::SignedSecurityEvent;
    pub(super) use chio_kernel::approval::ApprovalStore;
    pub(super) use chio_kernel::security_admission_operation::{
        AdmissionOperationKind, AdmissionOperationState, AdmissionOperationStore,
        ReplayReservationState,
    };
    pub(super) use chio_kernel::threshold_approval::{
        authorization_capability_hash, ThresholdApprovalProposal, ThresholdApprovalProposalBody,
        ThresholdApprovalRequirement,
    };
    pub(super) use chio_kernel::{
        ActiveResponseArtifactAuthorityAttestation, ActiveResponseArtifactAuthorityAttestationBody,
        ActiveResponseAuthorizationRequest, ActiveResponseCommittedDispatch,
        ActiveResponseExecutionApproval, ActiveResponseExecutionEvidence,
        ActiveResponseExecutionRequest, ActiveResponseExecutorAuthority,
        ActiveResponseExecutorAuthorityIdentity, ActiveResponseExecutorError,
        ActiveResponseFindingAuthority, ActiveResponseFindingAuthorityError,
        ActiveResponsePolicyResolutionError, ActiveResponseRequirement,
        ActiveResponseSubmissionProof, ActiveResponseSubmissionProofBody,
        AuthoritativeCorrelatedFindingEvidence, AutomaticActiveResponseDispatchFenceOutcome,
        ChioKernel, GovernedSecurityRuntimePublication, KernelConfig, KernelError,
        MemoryBudgetConfig, PreparedActiveResponseAdmission, SecurityDispatchOutcomeHandle,
        SecurityPreDispatchContext, SecurityPreDispatchHook, DEFAULT_CHECKPOINT_BATCH_SIZE,
        DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
    };
    pub(super) use chio_quarantine::{
        CorrelationOutcome, CorrelationPolicy, CorrelationStatus, RuleLimits, TemporalRule,
    };
    pub(super) use chio_security_kernel::{Clock, SecurityEventIngress};
    pub(super) use chio_security_types::ports::{
        AdmissionArtifactRef, AlertDeliveryQuery, AlertDeliveryStatus, ApprovalVerifierPort,
        AttestedFindingBatchBinding, AttestedFindingBatchBindings, AttestedFindingBatchKey,
        AttestedFindingBatchPublication, AttestedFindingBatchStore,
        AttestedFindingResponseAdmissionState, AttestedFindingResponseCompletionOutcome,
        AttestedFindingResponseCompletionState, AttestedFindingResponseOutboxHealth,
        AttestedFindingResponseOutboxKey, AttestedFindingResponseOutboxRecord,
        AttestedFindingResponseOutboxStore, AttestedFindingResponseOutboxTransition,
        AttestedFindingResponsePlanPublication, AttestedFindingResponsePlanningState,
        CanonicalBody, CorrelationIngressStore, CreateOutcome, Digest32, EffectExecutionStatus,
        EffectOperation, EffectPort, EffectRequest, EffectResult, EffectResultQuery, ErrorCode,
        EventAppend, EventId, GovernedApprovalRequest, GovernedApprovalReservationMutation,
        IssuanceFreezeAdmissionQuery, LeaseOwnerId, OpaqueReceiptRef, PortError, PortErrorKind,
        PortResult, PreparedActiveResponseDispatchBinding, ProducerId, ProducerTrustClass,
        RecordId, RuleId, SecurityAlert, SecurityAlertPort, SecurityEventVerifierPort, SessionId,
        TenantId, UnverifiedEventBatch, UnverifiedSecurityEvent, SecurityEventVerificationRecord,
    };
    pub(super) use chio_security_types::{
        OperatorCapabilityBinding, ResponseApprovalRequirement, ResponseEffectKind,
        ResponseEffectSpec, ResponseTarget, SecurityEventBody, SecurityEventBodyInput,
        SecurityEventKind, SecuritySeverity, SecuritySubject,
    };
    pub(super) use chio_store_sqlite::security_state::SqliteSecurityStateStore;
    pub(super) use chio_store_sqlite::{
        SqliteApprovalStore, SqliteBudgetStore, SqliteReceiptStore,
        SqliteSecurityAdmissionOperationStore,
    };
    pub(super) use rusqlite::Connection;
    pub(super) use serde_json::json;
    pub(super) use std::collections::BTreeMap;
    pub(super) use std::path::{Path, PathBuf};
    pub(super) use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    pub(super) use std::sync::{Arc, Barrier, Mutex};
    pub(super) use std::thread;
    pub(super) use std::time::{SystemTime, UNIX_EPOCH};

    pub(super) fn rejected<T, E>(result: Result<T, E>, message: &str) -> E {
        match result {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
    }

    pub(super) use super::test_clocks::{FixedClock, MutableClock, ToggleClock};

    pub(super) fn tenant() -> TenantId {
        TenantId::new("tenant-events").unwrap_or_else(|error| panic!("tenant id: {error}"))
    }

    pub(super) fn record(value: &str) -> RecordId {
        RecordId::new(value).unwrap_or_else(|error| panic!("record id: {error}"))
    }

    pub(super) fn checked_sqlite_count(value: i64, label: &str) -> u64 {
        match u64::try_from(value) {
            Ok(value) => value,
            Err(error) => panic!("{label} is outside the u64 range: {error}"),
        }
    }

    pub(super) fn producer() -> ProducerId {
        ProducerId::new("detector-production")
            .unwrap_or_else(|error| panic!("producer id: {error}"))
    }

    pub(super) fn receipt_producer() -> ProducerId {
        ProducerId::new("receipt-authority").unwrap_or_else(|error| panic!("producer id: {error}"))
    }

    pub(super) fn signed_event(keypair: &Keypair) -> UnverifiedSecurityEvent {
        signed_event_kind(
            "event-signed",
            SecurityEventKind::TripwireObservation,
            keypair,
        )
    }

    pub(super) fn signed_event_kind(
        event_id: &str,
        event_kind: SecurityEventKind,
        keypair: &Keypair,
    ) -> UnverifiedSecurityEvent {
        signed_event_kind_at(event_id, event_kind, 9_900, 10_000, keypair)
    }

    pub(super) fn signed_event_kind_at(
        event_id: &str,
        event_kind: SecurityEventKind,
        event_time_unix_ms: u64,
        ingest_time_unix_ms: u64,
        keypair: &Keypair,
    ) -> UnverifiedSecurityEvent {
        let body = SecurityEventBody::new(SecurityEventBodyInput {
            event_id: EventId::new(event_id).unwrap_or_else(|error| panic!("event id: {error}")),
            event_time_unix_ms,
            ingest_time_unix_ms,
            tenant_id: tenant(),
            subject: SecuritySubject {
                subject_id: record("subject-1"),
                agent_id: record("agent-1"),
                session_id: SessionId::new("session-1")
                    .unwrap_or_else(|error| panic!("session id: {error}")),
                capability_id: record("capability-1"),
                lineage_seed: chio_security_types::ports::LineageId::new("lineage-1")
                    .unwrap_or_else(|error| panic!("lineage id: {error}")),
            },
            source_receipt_id: OpaqueReceiptRef::new("receipt-source")
                .unwrap_or_else(|error| panic!("receipt id: {error}")),
            event_kind,
            severity: SecuritySeverity::High,
            evidence_references: vec![OpaqueReceiptRef::new("receipt-evidence")
                .unwrap_or_else(|error| panic!("evidence id: {error}"))],
            producer_id: producer(),
            producer_key_id: record("detector-key-v1"),
            trust_class: ProducerTrustClass::InternalDetector,
            policy_version: record("policy-v1"),
        })
        .unwrap_or_else(|error| panic!("event body: {error}"));
        let canonical_body =
            canonical_json_bytes(&body).unwrap_or_else(|error| panic!("canonical body: {error}"));
        let signed = SignedSecurityEvent::sign_with_backend(
            body.clone(),
            &Ed25519Backend::new(keypair.clone()),
        )
        .unwrap_or_else(|error| panic!("sign event: {error}"));
        let source_evidence = canonical_json_bytes(&signed)
            .unwrap_or_else(|error| panic!("canonical signed event: {error}"));
        UnverifiedSecurityEvent {
            tenant_id: body.tenant_id,
            event_id: body.event_id,
            producer_id: body.producer_id,
            event_time_unix_ms: body.event_time_unix_ms,
            received_at_unix_ms: body.ingest_time_unix_ms,
            canonical_body: CanonicalBody::new(canonical_body.clone())
                .unwrap_or_else(|error| panic!("canonical body: {error}")),
            body_hash: Digest32::new(*chio_core::sha256(&canonical_body).as_bytes()),
            source_evidence: CanonicalBody::new(source_evidence)
                .unwrap_or_else(|error| panic!("source evidence: {error}")),
        }
    }

    pub(super) fn verifier(keypair: &Keypair) -> NativeSecurityEventVerifier {
        NativeSecurityEventVerifier::new(
            Arc::new(FixedClock(10_000)),
            vec![TrustedSecurityEventProducer {
                tenant_id: tenant(),
                producer_id: producer(),
                producer_key_id: record("detector-key-v1"),
                policy_version: record("policy-v1"),
                producer_key: keypair.public_key(),
            }],
            Vec::new(),
            60_000,
            1_000,
        )
        .unwrap_or_else(|error| panic!("verifier: {error}"))
    }

    pub(super) fn receipt_event(
        keypair: &Keypair,
        tool_origin: ToolOrigin,
        event_time_unix_ms: u64,
        ingest_time_unix_ms: u64,
    ) -> UnverifiedSecurityEvent {
        let body = SecurityEventBody::new(SecurityEventBodyInput {
            event_id: EventId::new("event-receipt")
                .unwrap_or_else(|error| panic!("event id: {error}")),
            event_time_unix_ms,
            ingest_time_unix_ms,
            tenant_id: tenant(),
            subject: SecuritySubject {
                subject_id: record("subject-receipt"),
                agent_id: record("agent-receipt"),
                session_id: SessionId::new("session-receipt")
                    .unwrap_or_else(|error| panic!("session id: {error}")),
                capability_id: record("capability-receipt"),
                lineage_seed: chio_security_types::ports::LineageId::new("lineage-receipt")
                    .unwrap_or_else(|error| panic!("lineage id: {error}")),
            },
            source_receipt_id: OpaqueReceiptRef::new("receipt-projected-source")
                .unwrap_or_else(|error| panic!("receipt id: {error}")),
            event_kind: SecurityEventKind::TripwireObservation,
            severity: SecuritySeverity::High,
            evidence_references: vec![OpaqueReceiptRef::new("receipt-projected-evidence")
                .unwrap_or_else(|error| panic!("evidence id: {error}"))],
            producer_id: receipt_producer(),
            producer_key_id: record("receipt-key-v1"),
            trust_class: ProducerTrustClass::VerifiedReceipt,
            policy_version: record("policy-v1"),
        })
        .unwrap_or_else(|error| panic!("event body: {error}"));
        let canonical_body =
            canonical_json_bytes(&body).unwrap_or_else(|error| panic!("canonical body: {error}"));
        let body_hash = Digest32::new(*chio_core::sha256(&canonical_body).as_bytes());
        let projection = SecurityEventReceiptProjection {
            version: SECURITY_EVENT_RECEIPT_PROJECTION_VERSION.to_string(),
            body: body.clone(),
        };
        let action = ToolCallAction::from_parameters(json!({
            "event_id": body.event_id.as_str(),
            "producer_id": body.producer_id.as_str(),
            "projection_version": SECURITY_EVENT_RECEIPT_PROJECTION_VERSION,
        }))
        .unwrap_or_else(|error| panic!("receipt action: {error}"));
        let receipt = ChioReceipt::sign_with_backend(
            ChioReceiptBody {
                id: String::new(),
                timestamp: ingest_time_unix_ms / 1_000,
                capability_id: "chio.security-event.projection".to_string(),
                tool_server: "chio.kernel".to_string(),
                tool_name: "security_event".to_string(),
                action,
                decision: None,
                receipt_kind: ReceiptKind::TraceObservation,
                boundary_class: BoundaryClass::DetectOnly,
                observation_outcome: Some(ObservationOutcome::Observed),
                tool_origin,
                redaction_mode: RedactionMode::Redacted,
                actor_chain: Vec::new(),
                content_hash: hex::encode(body_hash.as_bytes()),
                policy_hash: hex::encode([9_u8; 32]),
                evidence: Vec::new(),
                metadata: Some(json!({"security_event_projection": projection})),
                trust_level: TrustLevel::Verified,
                tenant_id: Some(body.tenant_id.as_str().to_string()),
                kernel_key: keypair.public_key(),
                bbs_projection_version: None,
            },
            &Ed25519Backend::new(keypair.clone()),
        )
        .unwrap_or_else(|error| panic!("receipt sign: {error}"));
        let source_evidence = canonical_json_bytes(&receipt)
            .unwrap_or_else(|error| panic!("receipt evidence: {error}"));
        UnverifiedSecurityEvent {
            tenant_id: body.tenant_id,
            event_id: body.event_id,
            producer_id: body.producer_id,
            event_time_unix_ms: body.event_time_unix_ms,
            received_at_unix_ms: body.ingest_time_unix_ms,
            canonical_body: CanonicalBody::new(canonical_body)
                .unwrap_or_else(|error| panic!("canonical body: {error}")),
            body_hash,
            source_evidence: CanonicalBody::new(source_evidence)
                .unwrap_or_else(|error| panic!("source evidence: {error}")),
        }
    }

    pub(super) fn verifier_with_receipts(
        internal_keypair: &Keypair,
        receipt_keypair: &Keypair,
        clock: Arc<dyn Clock>,
    ) -> NativeSecurityEventVerifier {
        NativeSecurityEventVerifier::new(
            clock,
            vec![TrustedSecurityEventProducer {
                tenant_id: tenant(),
                producer_id: producer(),
                producer_key_id: record("detector-key-v1"),
                policy_version: record("policy-v1"),
                producer_key: internal_keypair.public_key(),
            }],
            vec![TrustedSecurityEventReceiptProducer {
                tenant_id: tenant(),
                producer_id: receipt_producer(),
                signer_key_id: record("receipt-key-v1"),
                signer_key: receipt_keypair.public_key(),
            }],
            60_000,
            1_000,
        )
        .unwrap_or_else(|error| panic!("verifier: {error}"))
    }
mod verifier_accepts_configured_internal_and_receipt_backed_provenance;

mod receipt_provenance_rejects_tampered_external_and_untrusted_sources;

mod receipt_provenance_binds_tenant_projection_and_freshness;

mod corrupted_signed_event_evidence_is_rejected_before_correlation;

mod otherwise_valid_event_from_untrusted_producer_is_rejected;

mod trusted_producer_signature_from_an_unconfigured_policy_is_rejected;

mod corrupt_tripwire_signature_cannot_enter_verified_persistence_or_correlation;


    #[derive(Default)]
    pub(super) struct RecordingPlanner {
        pub(super) batches: Mutex<Vec<AttestedFindingBatchPublication>>,
    }

    impl AttestedFindingBatchPlanner for RecordingPlanner {
        fn ensure_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn publish_attested_batch(
            &self,
            findings: &[AuthoritativeCorrelatedFindingEvidence],
        ) -> PortResult<()> {
            let publication = build_attested_finding_batch_publication(findings)?;
            self.batches
                .lock()
                .map_err(|_| PortError::unavailable())?
                .push(publication);
            Ok(())
        }

        fn load_published_attested_batch(
            &self,
            key: &AttestedFindingBatchKey,
        ) -> PortResult<AttestedFindingBatchPublication> {
            let batches = self.batches.lock().map_err(|_| PortError::unavailable())?;
            let publication = batches.last().ok_or_else(PortError::integrity_failure)?;
            if publication.body.tenant_id != key.tenant_id
                || publication.body.batch_id != key.batch_id
            {
                return Err(PortError::integrity_failure());
            }
            Ok(publication.clone())
        }
    }

    pub(super) struct TwoOutcomeCorrelation;

    impl CorrelationPort for TwoOutcomeCorrelation {
        fn ensure_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn accepts_policy(&self, _: &RecordId) -> bool {
            true
        }

        fn correlate(
            &self,
            _: &chio_security_types::ports::SecurityEventVerificationRecord,
            _: u64,
        ) -> PortResult<Vec<RuleCorrelationOutcome>> {
            Ok(["rule-one", "rule-two"]
                .into_iter()
                .map(|rule| RuleCorrelationOutcome::synthetic(RuleId::new(rule).unwrap_or_else(|error| panic!("rule id: {error}")), CorrelationOutcome {
                        status: CorrelationStatus::Matched,
                        findings: Vec::new(),
                        detector_health: Vec::new(),
                        automatic_response_suppressed: false,
                        watermark_unix_ms: 10_000,
                    }))
                .collect())
        }
    }

    pub(super) struct ToggleCorrelation {
        pub(super) ready: Arc<AtomicBool>,
    }

    impl CorrelationPort for ToggleCorrelation {
        fn ensure_ready(&self) -> PortResult<()> {
            if self.ready.load(Ordering::Acquire) {
                Ok(())
            } else {
                Err(PortError::unavailable())
            }
        }

        fn accepts_policy(&self, _: &RecordId) -> bool {
            true
        }

        fn correlate(
            &self,
            _: &chio_security_types::ports::SecurityEventVerificationRecord,
            _: u64,
        ) -> PortResult<Vec<RuleCorrelationOutcome>> {
            Ok(Vec::new())
        }
    }
mod consumer_readiness_rechecks_verifier_clock_and_correlation_store;


    pub(super) fn authoritative_finding_with_identity(
        finding_id: &str,
        rule_id: &str,
        hash_byte: u8,
    ) -> AuthoritativeCorrelatedFindingEvidence {
        let body: CorrelatedFindingReceiptBody = serde_json::from_value(json!({
            "header": {
                "schema_version": 1,
                "occurred_at_unix_ms": 10_000,
                "tenant_id": "tenant-events",
                "transition_id": "finding-transition",
                "prior_receipt_ids": ["receipt-source"]
            },
            "policy": {
                "policy_version": "policy-v1",
                "policy_hash": vec![31_u8; 32]
            },
            "finding_id": finding_id,
            "finding_hash": vec![hash_byte; 32],
            "rule_id": rule_id,
            "rule_version_hash": vec![hash_byte.saturating_add(1); 32],
            "group_key_hash": vec![34_u8; 32],
            "ordered_event_ids": ["event-signed"],
            "ordered_evidence_digests": [vec![35_u8; 32]],
            "ordered_source_receipt_ids": ["receipt-source"],
            "first_event_time_unix_ms": 9_900,
            "last_event_time_unix_ms": 9_950,
            "lineage_seed": "lineage-first"
        }))
        .unwrap_or_else(|error| panic!("finding body: {error}"));
        let closed = ActiveDefenseReceiptBody::CorrelatedFinding(body.clone());
        let evidence_id = closed
            .evidence_id()
            .unwrap_or_else(|error| panic!("evidence id: {error}"));
        AuthoritativeCorrelatedFindingEvidence::from_verified_signed_receipt(evidence_id, body)
            .unwrap_or_else(|error| panic!("authoritative finding: {error}"))
    }

    pub(super) fn authoritative_finding() -> AuthoritativeCorrelatedFindingEvidence {
        authoritative_finding_with_identity("finding-first", "rule-one", 32)
    }

    pub(super) fn reverse_lexicographic_findings() -> Vec<AuthoritativeCorrelatedFindingEvidence> {
        let mut findings = vec![
            authoritative_finding_with_identity("finding-order-a", "rule-one", 41),
            authoritative_finding_with_identity("finding-order-b", "rule-one", 51),
        ];
        findings.sort_by(|left, right| left.evidence_id().cmp(right.evidence_id()));
        findings.reverse();
        findings
    }

    pub(super) struct TestFindingAuthority {
        pub(super) findings: BTreeMap<OpaqueReceiptRef, AuthoritativeCorrelatedFindingEvidence>,
    }

    impl TestFindingAuthority {
        pub(super) fn new(findings: &[AuthoritativeCorrelatedFindingEvidence]) -> Self {
            Self {
                findings: findings
                    .iter()
                    .map(|finding| (finding.evidence_id().clone(), finding.clone()))
                    .collect(),
            }
        }
    }

    impl ActiveResponseFindingAuthority for TestFindingAuthority {
        fn ensure_ready(&self) -> Result<(), ActiveResponseFindingAuthorityError> {
            Ok(())
        }

        fn load_correlated_finding(
            &self,
            evidence_id: &OpaqueReceiptRef,
        ) -> Result<
            Option<AuthoritativeCorrelatedFindingEvidence>,
            ActiveResponseFindingAuthorityError,
        > {
            Ok(self.findings.get(evidence_id).cloned())
        }
    }

    pub(super) fn response_policy_selection() -> AttestedFindingResponsePolicySelection {
        let canonical_contribution = CanonicalBody::new(b"{\"maximum_invocations\":1}".to_vec())
            .unwrap_or_else(|error| panic!("policy contribution: {error}"));
        let contribution_hash =
            Digest32::new(*chio_core::sha256(canonical_contribution.as_bytes()).as_bytes());
        AttestedFindingResponsePolicySelection {
            execution: chio_security_types::ResponseExecutionBinding::new(
                chio_security_types::ResponseExecutionMode::Live,
            ),
            affected_ids: vec![record("affected-policy")],
            effects: vec![ResponseEffectSpec {
                kind: ResponseEffectKind::ThrottleSession,
                target: ResponseTarget::Session {
                    session_id: SessionId::new("session-policy")
                        .unwrap_or_else(|error| panic!("policy session: {error}")),
                },
                canonical_contribution,
                contribution_hash,
                observed_base_version_hash: Digest32::new([71_u8; 32]),
            }],
            ttl_ms: 1_000,
            created_at_unix_ms: 10_001,
            operator_capability: OperatorCapabilityBinding {
                capability_id: record("policy-capability"),
                capability_digest: Digest32::new([72_u8; 32]),
                expires_at_unix_ms: 20_000,
                executor_subject: record("policy-executor"),
            },
            approval_requirement: ResponseApprovalRequirement::Automatic,
            submitter: record("policy-submitter"),
            reason_hash: Digest32::new([73_u8; 32]),
            admission_artifact_ref: AdmissionArtifactRef::new("policy-artifacts")
                .unwrap_or_else(|error| panic!("policy artifact ref: {error}")),
        }
    }

    pub(super) struct RecordingResponsePolicy;

    impl AttestedFindingResponsePolicyPlanner for RecordingResponsePolicy {
        fn ensure_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn trusted_artifact_authority(&self) -> PortResult<chio_core::PublicKey> {
            Ok(Keypair::from_seed(&[91_u8; 32]).public_key())
        }

        fn select_response_policy(
            &self,
            _: &AuthoritativeCorrelatedFindingEvidence,
            _: &chio_security_types::ports::AttestedFindingBatchBinding,
        ) -> PortResult<AttestedFindingResponsePolicySelection> {
            Ok(response_policy_selection())
        }

        fn load_admission_artifacts(
            &self,
            _: &ReservedAttestedFindingResponsePlan,
            artifact_ref: &AdmissionArtifactRef,
        ) -> PortResult<AttestedFindingAdmissionArtifacts> {
            if artifact_ref.as_str() != "policy-artifacts" {
                return Err(PortError::integrity_failure());
            }
            Ok(AttestedFindingAdmissionArtifacts::synthetic(Digest32::new(
                [74_u8; 32],
            )))
        }
    }

    #[derive(Default)]
    pub(super) struct RecordingResponseCoordinator {
        pub(super) executions: Mutex<Vec<(String, String)>>,
    }

    impl AttestedFindingResponseCoordinator for RecordingResponseCoordinator {
        fn ensure_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn recover_committed(
            &self,
            _: &chio_security_types::ResponsePlan,
            _: &RecordId,
        ) -> PortResult<Option<AttestedFindingResponseCompletionProof>> {
            Ok(None)
        }

        fn resume_dispatch_committed(
            &self,
            _: &chio_security_types::ResponsePlan,
            _: &PreparedActiveResponseDispatchBinding,
        ) -> PortResult<AttestedFindingDispatchCommittedResume> {
            Ok(AttestedFindingDispatchCommittedResume::NotDispatchCommitted)
        }

        fn reconstruct_pre_dispatch(
            &self,
            plan: &ReservedAttestedFindingResponsePlan,
            artifacts: AttestedFindingAdmissionArtifacts,
            binding: &PreparedActiveResponseDispatchBinding,
        ) -> PortResult<AttestedFindingPreDispatchReconstruction> {
            let prepared = self.prepare_admission(plan, artifacts)?;
            if prepared.durable_dispatch_binding(plan.response_plan())? != *binding {
                return Err(PortError::integrity_failure());
            }
            Ok(AttestedFindingPreDispatchReconstruction::Prepared(
                Box::new(prepared),
            ))
        }

        fn terminate_never_committed(
            &self,
            _: &chio_security_types::ResponsePlan,
            _: &PreparedActiveResponseDispatchBinding,
            _: Option<&AttestedFindingAdmissionArtifacts>,
        ) -> PortResult<()> {
            Err(PortError::integrity_failure())
        }

        fn prepare_admission(
            &self,
            plan: &ReservedAttestedFindingResponsePlan,
            _: AttestedFindingAdmissionArtifacts,
        ) -> PortResult<PreparedAttestedFindingResponse> {
            let dispatch_id = RecordId::new(format!(
                "test-dispatch-{}",
                plan.response_plan().action_id.as_str()
            ))
            .map_err(|_| PortError::integrity_failure())?;
            Ok(PreparedAttestedFindingResponse::synthetic(dispatch_id))
        }

        fn cancel_prepared(
            &self,
            _: &ReservedAttestedFindingResponsePlan,
            _: &PreparedAttestedFindingResponse,
        ) -> PortResult<()> {
            Ok(())
        }

        fn execute_prepared(
            &self,
            plan: &ReservedAttestedFindingResponsePlan,
            prepared: PreparedAttestedFindingResponse,
        ) -> PortResult<AttestedFindingResponseCompletionProof> {
            let dispatch_id = prepared.dispatch_id().clone();
            self.executions
                .lock()
                .map_err(|_| PortError::unavailable())?
                .push((
                    plan.response_plan().action_id.as_str().to_owned(),
                    dispatch_id.as_str().to_owned(),
                ));
            Ok(AttestedFindingResponseCompletionProof::synthetic(
                dispatch_id,
                AttestedFindingResponseCompletionOutcome::Activated,
                OpaqueReceiptRef::new("test-response-completion")
                    .map_err(|_| PortError::integrity_failure())?,
                Digest32::new([75_u8; 32]),
            ))
        }
    }

    #[derive(Default)]
    pub(super) struct ArtifactEnforcingCoordinator {
        pub(super) effects_applied: AtomicBool,
    }

    impl AttestedFindingResponseCoordinator for ArtifactEnforcingCoordinator {
        fn ensure_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn recover_committed(
            &self,
            _: &chio_security_types::ResponsePlan,
            _: &RecordId,
        ) -> PortResult<Option<AttestedFindingResponseCompletionProof>> {
            Ok(None)
        }

        fn resume_dispatch_committed(
            &self,
            _: &chio_security_types::ResponsePlan,
            _: &PreparedActiveResponseDispatchBinding,
        ) -> PortResult<AttestedFindingDispatchCommittedResume> {
            Ok(AttestedFindingDispatchCommittedResume::NotDispatchCommitted)
        }

        fn reconstruct_pre_dispatch(
            &self,
            plan: &ReservedAttestedFindingResponsePlan,
            artifacts: AttestedFindingAdmissionArtifacts,
            binding: &PreparedActiveResponseDispatchBinding,
        ) -> PortResult<AttestedFindingPreDispatchReconstruction> {
            let prepared = self.prepare_admission(plan, artifacts)?;
            if prepared.durable_dispatch_binding(plan.response_plan())? != *binding {
                return Err(PortError::integrity_failure());
            }
            Ok(AttestedFindingPreDispatchReconstruction::Prepared(
                Box::new(prepared),
            ))
        }

        fn terminate_never_committed(
            &self,
            _: &chio_security_types::ResponsePlan,
            _: &PreparedActiveResponseDispatchBinding,
            _: Option<&AttestedFindingAdmissionArtifacts>,
        ) -> PortResult<()> {
            Err(PortError::integrity_failure())
        }

        fn prepare_admission(
            &self,
            plan: &ReservedAttestedFindingResponsePlan,
            _: AttestedFindingAdmissionArtifacts,
        ) -> PortResult<PreparedAttestedFindingResponse> {
            Ok(PreparedAttestedFindingResponse::synthetic(
                RecordId::new(format!(
                    "artifact-dispatch-{}",
                    plan.response_plan().action_id.as_str()
                ))
                .map_err(|_| PortError::integrity_failure())?,
            ))
        }

        fn cancel_prepared(
            &self,
            _: &ReservedAttestedFindingResponsePlan,
            _: &PreparedAttestedFindingResponse,
        ) -> PortResult<()> {
            Ok(())
        }

        fn execute_prepared(
            &self,
            _: &ReservedAttestedFindingResponsePlan,
            prepared: PreparedAttestedFindingResponse,
        ) -> PortResult<AttestedFindingResponseCompletionProof> {
            self.effects_applied.store(true, Ordering::Release);
            Ok(AttestedFindingResponseCompletionProof::synthetic(
                prepared.dispatch_id().clone(),
                AttestedFindingResponseCompletionOutcome::Activated,
                OpaqueReceiptRef::new("artifact-response-completion")
                    .map_err(|_| PortError::integrity_failure())?,
                Digest32::new([76_u8; 32]),
            ))
        }
    }

    pub(super) struct MissingArtifactResponsePolicy;

    impl AttestedFindingResponsePolicyPlanner for MissingArtifactResponsePolicy {
        fn ensure_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn trusted_artifact_authority(&self) -> PortResult<chio_core::PublicKey> {
            Ok(Keypair::from_seed(&[91_u8; 32]).public_key())
        }

        fn select_response_policy(
            &self,
            _: &AuthoritativeCorrelatedFindingEvidence,
            _: &chio_security_types::ports::AttestedFindingBatchBinding,
        ) -> PortResult<AttestedFindingResponsePolicySelection> {
            Ok(response_policy_selection())
        }
    }

    pub(super) struct SelectiveArtifactResponsePolicy {
        pub(super) rejected: BTreeMap<OpaqueReceiptRef, ErrorCode>,
    }

    impl AttestedFindingResponsePolicyPlanner for SelectiveArtifactResponsePolicy {
        fn ensure_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn trusted_artifact_authority(&self) -> PortResult<chio_core::PublicKey> {
            Ok(Keypair::from_seed(&[91_u8; 32]).public_key())
        }

        fn select_response_policy(
            &self,
            _: &AuthoritativeCorrelatedFindingEvidence,
            _: &AttestedFindingBatchBinding,
        ) -> PortResult<AttestedFindingResponsePolicySelection> {
            Ok(response_policy_selection())
        }

        fn load_admission_artifacts(
            &self,
            plan: &ReservedAttestedFindingResponsePlan,
            _: &AdmissionArtifactRef,
        ) -> PortResult<AttestedFindingAdmissionArtifacts> {
            if let Some(error_code) = self.rejected.get(&plan.binding().evidence_id) {
                return Err(PortError::new(
                    PortErrorKind::InvalidData,
                    error_code.clone(),
                ));
            }
            Ok(AttestedFindingAdmissionArtifacts::synthetic(Digest32::new(
                [74_u8; 32],
            )))
        }
    }

    pub(super) struct OneFindingCorrelation;

    impl CorrelationPort for OneFindingCorrelation {
        fn ensure_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn accepts_policy(&self, _: &RecordId) -> bool {
            true
        }

        fn correlate(
            &self,
            _: &chio_security_types::ports::SecurityEventVerificationRecord,
            _: u64,
        ) -> PortResult<Vec<RuleCorrelationOutcome>> {
            Ok(vec![RuleCorrelationOutcome::synthetic(RuleId::new("rule-one").unwrap_or_else(|error| panic!("rule id: {error}")), CorrelationOutcome {
                    status: CorrelationStatus::Matched,
                    findings: Vec::new(),
                    detector_health: Vec::new(),
                    automatic_response_suppressed: false,
                    watermark_unix_ms: 10_000,
                })])
        }
    }

    pub(super) struct OneFindingAttestor;

    impl CorrelationAttestor for OneFindingAttestor {
        fn ensure_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn attest(
            &self,
            _: &CorrelationOutcome,
        ) -> PortResult<Vec<AuthoritativeCorrelatedFindingEvidence>> {
            Ok(vec![authoritative_finding()])
        }
    }

    pub(super) struct FailOnceAttestor {
        pub(super) fail: AtomicBool,
    }

    impl CorrelationAttestor for FailOnceAttestor {
        fn ensure_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn attest(
            &self,
            _: &CorrelationOutcome,
        ) -> PortResult<Vec<AuthoritativeCorrelatedFindingEvidence>> {
            if self.fail.swap(false, Ordering::AcqRel) {
                Err(PortError::unavailable())
            } else {
                Ok(vec![authoritative_finding()])
            }
        }
    }

    pub(super) struct AckLossCorrelationIngressStore {
        pub(super) inner: Arc<SqliteSecurityStateStore>,
        pub(super) lose_ack: AtomicBool,
    }

    impl CorrelationIngressStore for AckLossCorrelationIngressStore {
        fn ensure_correlation_ingress_ready(&self) -> PortResult<()> {
            self.inner.ensure_correlation_ingress_ready()
        }

        fn enqueue_verified_correlation_event(
            &self,
            event: &UnverifiedSecurityEvent,
            verified: &SecurityEventVerificationRecord,
        ) -> PortResult<EventAppend> {
            self.inner
                .enqueue_verified_correlation_event(event, verified)
        }

        fn load_pending_correlation_events(
            &self,
            max_results: u32,
        ) -> PortResult<UnverifiedEventBatch> {
            self.inner.load_pending_correlation_events(max_results)
        }

        fn validate_pending_correlation_event(
            &self,
            event: &UnverifiedSecurityEvent,
            verified: &SecurityEventVerificationRecord,
        ) -> PortResult<()> {
            self.inner
                .validate_pending_correlation_event(event, verified)
        }

        fn acknowledge_correlated_event(&self, event: &UnverifiedSecurityEvent) -> PortResult<()> {
            self.inner.acknowledge_correlated_event(event)?;
            if self.lose_ack.swap(false, Ordering::AcqRel) {
                Err(PortError::unavailable())
            } else {
                Ok(())
            }
        }

        fn count_pending_correlation_events(&self) -> PortResult<u64> {
            self.inner.count_pending_correlation_events()
        }
    }

    pub(super) struct AckLossAttestedFindingBatchPlanner {
        pub(super) inner: Arc<dyn AttestedFindingBatchPlanner>,
        pub(super) lose_publish_ack: AtomicBool,
    }

    impl AttestedFindingBatchPlanner for AckLossAttestedFindingBatchPlanner {
        fn ensure_ready(&self) -> PortResult<()> {
            self.inner.ensure_ready()
        }

        fn publish_attested_batch(
            &self,
            findings: &[AuthoritativeCorrelatedFindingEvidence],
        ) -> PortResult<()> {
            self.inner.publish_attested_batch(findings)?;
            if self.lose_publish_ack.swap(false, Ordering::AcqRel) {
                Err(PortError::unavailable())
            } else {
                Ok(())
            }
        }

        fn load_published_attested_batch(
            &self,
            key: &AttestedFindingBatchKey,
        ) -> PortResult<AttestedFindingBatchPublication> {
            self.inner.load_published_attested_batch(key)
        }
    }

    pub(super) fn correlation_consumer(
        keypair: &Keypair,
        planner: Arc<dyn AttestedFindingBatchPlanner>,
    ) -> Arc<ProductionCorrelationConsumer> {
        Arc::new(
            ProductionCorrelationConsumer::from_parts(
                Arc::new(verifier(keypair)),
                Arc::new(OneFindingCorrelation),
                Arc::new(OneFindingAttestor),
                planner,
            )
            .unwrap_or_else(|error| panic!("consumer: {error}")),
        )
    }

    pub(super) fn native_tripwire_rule() -> TemporalRule {
        TemporalRule::parse_json(
            br#"{
                "rule_id":"rule-native-tripwire-journal",
                "policy_version":"policy-v1",
                "group_by":"lineage_seed",
                "max_groups":16,
                "max_partial_matches_per_group":16,
                "allow_event_reuse":false,
                "stages":[{
                    "name":"tripwire",
                    "event_kind":"canary_invocation",
                    "minimum_severity":"high"
                }]
            }"#,
            &RuleLimits::default(),
        )
        .unwrap_or_else(|error| panic!("native tripwire rule: {error}"))
    }

    pub(super) fn native_correlation_policy() -> CorrelationPolicy {
        CorrelationPolicy::new(0, 4_096, 8, false)
            .unwrap_or_else(|error| panic!("native correlation policy: {error}"))
    }
mod idle_watermark_finalizes_a_single_tail_event_without_a_later_event;

mod future_fifo_prefix_does_not_starve_a_later_due_event;


    pub(super) fn durable_test_planner(
        store: &Arc<SqliteSecurityStateStore>,
    ) -> Arc<DurableAttestedFindingBatchPlanner> {
        let finding = authoritative_finding();
        Arc::new(
            DurableAttestedFindingBatchPlanner::new(
                Arc::clone(store) as Arc<dyn AttestedFindingBatchStore>,
                Arc::clone(store) as Arc<dyn AttestedFindingResponseOutboxStore>,
                Arc::new(TestFindingAuthority::new(std::slice::from_ref(&finding))),
                Arc::new(RecordingResponsePolicy),
                Arc::new(RecordingResponseCoordinator::default()),
                Arc::new(FixedClock(10_002)),
            )
            .unwrap_or_else(|error| panic!("durable planner: {error}")),
        )
    }


mod native_tripwire_ingress_recovers_and_persists_response_work_for_every_event_class;


    mod temporal_ingress;
mod correlation_ingress_ack_loss_keeps_the_durable_tombstone_and_does_not_republish;

mod response_publication_ack_loss_retries_without_duplicate_batch_or_outbox_work;

mod attestation_failure_leaves_ingress_pending_until_response_work_is_durable;

mod synchronous_consume_persists_ingress_before_downstream_failure;


    pub(super) struct ReverseLexicographicAttestor;

    impl CorrelationAttestor for ReverseLexicographicAttestor {
        fn ensure_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn attest(
            &self,
            _: &CorrelationOutcome,
        ) -> PortResult<Vec<AuthoritativeCorrelatedFindingEvidence>> {
            Ok(reverse_lexicographic_findings())
        }
    }

    #[derive(Default)]
    pub(super) struct DropAllPlanner {
        pub(super) published: AtomicBool,
    }

    impl AttestedFindingBatchPlanner for DropAllPlanner {
        fn ensure_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn publish_attested_batch(
            &self,
            _: &[AuthoritativeCorrelatedFindingEvidence],
        ) -> PortResult<()> {
            self.published.store(true, Ordering::Release);
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    pub(super) enum ReadbackMutation {
        Reverse,
        DropLast,
    }

    pub(super) struct MutatingReadbackPlanner {
        pub(super) publication: Mutex<Option<AttestedFindingBatchPublication>>,
        pub(super) mutation: ReadbackMutation,
    }

    impl MutatingReadbackPlanner {
        fn new(mutation: ReadbackMutation) -> Self {
            Self {
                publication: Mutex::new(None),
                mutation,
            }
        }
    }

    impl AttestedFindingBatchPlanner for MutatingReadbackPlanner {
        fn ensure_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn publish_attested_batch(
            &self,
            findings: &[AuthoritativeCorrelatedFindingEvidence],
        ) -> PortResult<()> {
            let publication = build_attested_finding_batch_publication(findings)?;
            *self
                .publication
                .lock()
                .map_err(|_| PortError::unavailable())? = Some(publication);
            Ok(())
        }

        fn load_published_attested_batch(
            &self,
            _: &AttestedFindingBatchKey,
        ) -> PortResult<AttestedFindingBatchPublication> {
            let mut publication = self
                .publication
                .lock()
                .map_err(|_| PortError::unavailable())?
                .clone()
                .ok_or_else(PortError::integrity_failure)?;
            let mut bindings = publication.body.bindings.clone().into_vec();
            match self.mutation {
                ReadbackMutation::Reverse => bindings.reverse(),
                ReadbackMutation::DropLast => {
                    bindings.pop();
                }
            }
            publication.body.bindings = AttestedFindingBatchBindings::new(bindings)
                .map_err(|_| PortError::integrity_failure())?;
            Ok(publication)
        }
    }
mod production_consumer_rejects_drop_all_planner_without_read_after_write_proof;

mod production_consumer_accepts_and_reports_the_exact_persisted_finding_batch;

mod production_consumer_preserves_the_exact_persisted_finding_order;

mod durable_production_planner_reloads_the_exact_batch_after_restart;

mod durable_production_planner_cannot_report_success_without_admission_artifacts;

mod production_response_coordinator_rejects_a_kernel_without_governed_runtime;

mod production_consumer_rejects_reordered_durable_response_bindings;

mod production_consumer_rejects_partial_durable_response_bindings;


    pub(super) struct FailSecondAttestation {
        pub(super) calls: Mutex<u32>,
    }

    impl CorrelationAttestor for FailSecondAttestation {
        fn ensure_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn attest(
            &self,
            _: &CorrelationOutcome,
        ) -> PortResult<Vec<AuthoritativeCorrelatedFindingEvidence>> {
            let mut calls = self.calls.lock().map_err(|_| PortError::unavailable())?;
            *calls = calls.saturating_add(1);
            if *calls == 2 {
                Err(PortError::integrity_failure())
            } else {
                Ok(vec![authoritative_finding()])
            }
        }
    }
mod attestation_failure_never_partially_publishes_raw_findings_to_planning;


    pub(super) struct RecoveryPolicy {
        pub(super) artifacts_unavailable: bool,
    }

    impl AttestedFindingResponsePolicyPlanner for RecoveryPolicy {
        fn ensure_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn trusted_artifact_authority(&self) -> PortResult<chio_core::PublicKey> {
            Ok(Keypair::from_seed(&[91_u8; 32]).public_key())
        }

        fn select_response_policy(
            &self,
            _: &AuthoritativeCorrelatedFindingEvidence,
            _: &chio_security_types::ports::AttestedFindingBatchBinding,
        ) -> PortResult<AttestedFindingResponsePolicySelection> {
            let mut selection = response_policy_selection();
            selection.ttl_ms = 100_000;
            selection.operator_capability.expires_at_unix_ms = 200_000;
            Ok(selection)
        }

        fn load_admission_artifacts(
            &self,
            _: &ReservedAttestedFindingResponsePlan,
            _: &AdmissionArtifactRef,
        ) -> PortResult<AttestedFindingAdmissionArtifacts> {
            if self.artifacts_unavailable {
                Err(PortError::unavailable())
            } else {
                Ok(AttestedFindingAdmissionArtifacts::synthetic(Digest32::new([
                    74_u8; 32
                ])))
            }
        }
    }

    pub(super) struct GovernedRecoveryPolicy {
        pub(super) artifacts_unavailable: bool,
    }

    impl AttestedFindingResponsePolicyPlanner for GovernedRecoveryPolicy {
        fn ensure_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn trusted_artifact_authority(&self) -> PortResult<chio_core::PublicKey> {
            Ok(Keypair::from_seed(&[91_u8; 32]).public_key())
        }

        fn select_response_policy(
            &self,
            _: &AuthoritativeCorrelatedFindingEvidence,
            _: &chio_security_types::ports::AttestedFindingBatchBinding,
        ) -> PortResult<AttestedFindingResponsePolicySelection> {
            let mut selection = response_policy_selection();
            selection.ttl_ms = 100_000;
            selection.operator_capability.expires_at_unix_ms = 200_000;
            selection.approval_requirement = ResponseApprovalRequirement::Governed {
                policy_id: record("governed-recovery-policy"),
            };
            Ok(selection)
        }

        fn load_admission_artifacts(
            &self,
            _: &ReservedAttestedFindingResponsePlan,
            _: &AdmissionArtifactRef,
        ) -> PortResult<AttestedFindingAdmissionArtifacts> {
            if self.artifacts_unavailable {
                Err(PortError::unavailable())
            } else {
                Ok(AttestedFindingAdmissionArtifacts::synthetic(Digest32::new([
                    74_u8; 32
                ])))
            }
        }
    }

    pub(super) struct RecoveryCoordinator {
        pub(super) fail_prepare: bool,
        pub(super) fail_execute: bool,
        pub(super) never_committed: bool,
        pub(super) allow_expired_termination: bool,
        pub(super) live_ready: bool,
        pub(super) committed_recovery: Option<(Digest32, AttestedFindingResponseCompletionProof)>,
        pub(super) dispatch_committed_recovery:
            Option<(Digest32, AttestedFindingResponseCompletionProof)>,
        pub(super) resume_integrity_failure: bool,
        pub(super) recovery_calls: Option<Arc<AtomicUsize>>,
        pub(super) resume_calls: Option<Arc<AtomicUsize>>,
        pub(super) termination_calls: Arc<AtomicUsize>,
        pub(super) cancel_calls: Arc<AtomicUsize>,
        pub(super) effects: Arc<AtomicUsize>,
    }

    impl RecoveryCoordinator {
        fn new(fail_prepare: bool, fail_execute: bool, effects: Arc<AtomicUsize>) -> Self {
            Self {
                fail_prepare,
                fail_execute,
                never_committed: false,
                allow_expired_termination: false,
                live_ready: true,
                committed_recovery: None,
                dispatch_committed_recovery: None,
                resume_integrity_failure: false,
                recovery_calls: None,
                resume_calls: None,
                termination_calls: Arc::new(AtomicUsize::new(0)),
                cancel_calls: Arc::new(AtomicUsize::new(0)),
                effects,
            }
        }

        fn never_committed(
            effects: Arc<AtomicUsize>,
            termination_calls: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                fail_prepare: false,
                fail_execute: false,
                never_committed: true,
                allow_expired_termination: false,
                live_ready: true,
                committed_recovery: None,
                dispatch_committed_recovery: None,
                resume_integrity_failure: false,
                recovery_calls: None,
                resume_calls: None,
                termination_calls,
                cancel_calls: Arc::new(AtomicUsize::new(0)),
                effects,
            }
        }

        fn expired_never_committed(
            effects: Arc<AtomicUsize>,
            termination_calls: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                fail_prepare: true,
                fail_execute: true,
                never_committed: true,
                allow_expired_termination: true,
                live_ready: false,
                committed_recovery: None,
                dispatch_committed_recovery: None,
                resume_integrity_failure: false,
                recovery_calls: None,
                resume_calls: None,
                termination_calls,
                cancel_calls: Arc::new(AtomicUsize::new(0)),
                effects,
            }
        }

        fn committed(
            plan_hash: Digest32,
            proof: AttestedFindingResponseCompletionProof,
            recovery_calls: Arc<AtomicUsize>,
            effects: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                fail_prepare: true,
                fail_execute: true,
                never_committed: false,
                allow_expired_termination: false,
                live_ready: false,
                committed_recovery: Some((plan_hash, proof)),
                dispatch_committed_recovery: None,
                resume_integrity_failure: false,
                recovery_calls: Some(recovery_calls),
                resume_calls: None,
                termination_calls: Arc::new(AtomicUsize::new(0)),
                cancel_calls: Arc::new(AtomicUsize::new(0)),
                effects,
            }
        }

        fn dispatch_committed(
            plan_hash: Digest32,
            proof: AttestedFindingResponseCompletionProof,
            resume_calls: Arc<AtomicUsize>,
            effects: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                fail_prepare: true,
                fail_execute: true,
                never_committed: false,
                allow_expired_termination: false,
                live_ready: false,
                committed_recovery: None,
                dispatch_committed_recovery: Some((plan_hash, proof)),
                resume_integrity_failure: false,
                recovery_calls: None,
                resume_calls: Some(resume_calls),
                termination_calls: Arc::new(AtomicUsize::new(0)),
                cancel_calls: Arc::new(AtomicUsize::new(0)),
                effects,
            }
        }

        fn resume_integrity_failure(
            resume_calls: Arc<AtomicUsize>,
            termination_calls: Arc<AtomicUsize>,
            effects: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                fail_prepare: true,
                fail_execute: true,
                never_committed: false,
                allow_expired_termination: false,
                live_ready: false,
                committed_recovery: None,
                dispatch_committed_recovery: None,
                resume_integrity_failure: true,
                recovery_calls: None,
                resume_calls: Some(resume_calls),
                termination_calls,
                cancel_calls: Arc::new(AtomicUsize::new(0)),
                effects,
            }
        }

        fn with_cancel_calls(mut self, cancel_calls: Arc<AtomicUsize>) -> Self {
            self.cancel_calls = cancel_calls;
            self
        }
    }

    impl AttestedFindingResponseCoordinator for RecoveryCoordinator {
        fn ensure_configured(&self) -> PortResult<()> {
            Ok(())
        }

        fn ensure_ready(&self) -> PortResult<()> {
            if self.live_ready {
                Ok(())
            } else {
                Err(PortError::unavailable())
            }
        }

        fn recover_committed(
            &self,
            response_plan: &chio_security_types::ResponsePlan,
            dispatch_id: &RecordId,
        ) -> PortResult<Option<AttestedFindingResponseCompletionProof>> {
            let Some((expected_plan_hash, proof)) = self.committed_recovery.as_ref() else {
                return Ok(None);
            };
            if &response_plan.plan_hash != expected_plan_hash
                || proof.dispatch_id() != dispatch_id
            {
                return Err(PortError::integrity_failure());
            }
            if let Some(calls) = self.recovery_calls.as_ref() {
                calls.fetch_add(1, Ordering::AcqRel);
            }
            Ok(Some(proof.clone()))
        }

        fn resume_dispatch_committed(
            &self,
            response_plan: &chio_security_types::ResponsePlan,
            binding: &PreparedActiveResponseDispatchBinding,
        ) -> PortResult<AttestedFindingDispatchCommittedResume> {
            if let Some(calls) = self.resume_calls.as_ref() {
                calls.fetch_add(1, Ordering::AcqRel);
            }
            if self.resume_integrity_failure {
                return Err(PortError::integrity_failure());
            }
            let Some((expected_plan_hash, proof)) =
                self.dispatch_committed_recovery.as_ref()
            else {
                return Ok(AttestedFindingDispatchCommittedResume::NotDispatchCommitted);
            };
            if &response_plan.plan_hash != expected_plan_hash
                || binding.validate_for_plan(response_plan).is_err()
                || proof.dispatch_id() != &binding.dispatch_id
            {
                return Err(PortError::integrity_failure());
            }
            Ok(AttestedFindingDispatchCommittedResume::Completed(
                proof.clone(),
            ))
        }

        fn reconstruct_pre_dispatch(
            &self,
            plan: &ReservedAttestedFindingResponsePlan,
            artifacts: AttestedFindingAdmissionArtifacts,
            binding: &PreparedActiveResponseDispatchBinding,
        ) -> PortResult<AttestedFindingPreDispatchReconstruction> {
            let prepared = self.prepare_admission(plan, artifacts)?;
            if prepared.durable_dispatch_binding(plan.response_plan())? != *binding {
                return Err(PortError::integrity_failure());
            }
            Ok(AttestedFindingPreDispatchReconstruction::Prepared(Box::new(
                prepared,
            )))
        }

        fn terminate_never_committed(
            &self,
            response_plan: &chio_security_types::ResponsePlan,
            binding: &PreparedActiveResponseDispatchBinding,
            current_artifacts: Option<&AttestedFindingAdmissionArtifacts>,
        ) -> PortResult<()> {
            if !self.never_committed
                || binding.validate_for_plan(response_plan).is_err()
            {
                return Err(PortError::integrity_failure());
            }
            if current_artifacts.is_none() && !self.allow_expired_termination {
                return Err(PortError::integrity_failure());
            }
            self.termination_calls.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        fn prepare_admission(
            &self,
            plan: &ReservedAttestedFindingResponsePlan,
            _: AttestedFindingAdmissionArtifacts,
        ) -> PortResult<PreparedAttestedFindingResponse> {
            if plan.response_plan().policy_hash != Digest32::new([31_u8; 32])
                || plan.admission_artifact_digest() != Some(&Digest32::new([74_u8; 32]))
            {
                return Err(PortError::integrity_failure());
            }
            if self.fail_prepare {
                return Err(PortError::unavailable());
            }
            Ok(PreparedAttestedFindingResponse::synthetic(
                RecordId::new(format!(
                    "recovery-dispatch-{}",
                    plan.response_plan().action_id.as_str()
                ))
                .map_err(|_| PortError::integrity_failure())?,
            ))
        }

        fn cancel_prepared(
            &self,
            _: &ReservedAttestedFindingResponsePlan,
            _: &PreparedAttestedFindingResponse,
        ) -> PortResult<()> {
            self.cancel_calls.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        fn execute_prepared(
            &self,
            plan: &ReservedAttestedFindingResponsePlan,
            prepared: PreparedAttestedFindingResponse,
        ) -> PortResult<AttestedFindingResponseCompletionProof> {
            if self.never_committed {
                return Err(PortError::new(
                    PortErrorKind::InvalidData,
                    ErrorCode::new("active_response.never_committed")
                        .map_err(|_| PortError::integrity_failure())?,
                ));
            }
            if self.fail_execute {
                return Err(PortError::unavailable());
            }
            self.effects.fetch_add(1, Ordering::AcqRel);
            Ok(AttestedFindingResponseCompletionProof::synthetic(
                prepared.dispatch_id().clone(),
                AttestedFindingResponseCompletionOutcome::Activated,
                OpaqueReceiptRef::new(format!(
                    "recovery-evidence-{}",
                    plan.response_plan().action_id.as_str()
                ))
                .map_err(|_| PortError::integrity_failure())?,
                Digest32::new([75_u8; 32]),
            ))
        }
    }

    pub(super) fn publish_recovery_batch(
        store: &SqliteSecurityStateStore,
        findings: &[AuthoritativeCorrelatedFindingEvidence],
    ) -> AttestedFindingBatchPublication {
        let publication = build_attested_finding_batch_publication(findings)
            .unwrap_or_else(|error| panic!("recovery publication: {error}"));
        store
            .publish_attested_finding_batch(&publication)
            .unwrap_or_else(|error| panic!("publish recovery batch: {error}"));
        publication
    }

    pub(super) fn recovery_planner(
        store: Arc<SqliteSecurityStateStore>,
        findings: &[AuthoritativeCorrelatedFindingEvidence],
        policy: Arc<dyn AttestedFindingResponsePolicyPlanner>,
        coordinator: Arc<dyn AttestedFindingResponseCoordinator>,
        clock: Arc<dyn Clock>,
    ) -> DurableAttestedFindingBatchPlanner {
        DurableAttestedFindingBatchPlanner::new(
            Arc::clone(&store) as Arc<dyn AttestedFindingBatchStore>,
            store as Arc<dyn AttestedFindingResponseOutboxStore>,
            Arc::new(TestFindingAuthority::new(findings)),
            policy,
            coordinator,
            clock,
        )
        .unwrap_or_else(|error| panic!("recovery planner: {error}"))
    }

    pub(super) struct RejectingGlobalScanOutboxStore {
        pub(super) inner: Arc<SqliteSecurityStateStore>,
        pub(super) global_scan_called: Arc<AtomicBool>,
    }

    #[derive(Clone, Copy)]
    pub(super) enum AdmissionPreparedFailureMode {
        BeforeWrite,
        AfterWrite,
    }

    pub(super) struct FailingAdmissionPreparedOutboxStore {
        pub(super) inner: Arc<SqliteSecurityStateStore>,
        pub(super) fail_next_admission_prepared: AtomicBool,
        pub(super) mode: AdmissionPreparedFailureMode,
    }

    impl FailingAdmissionPreparedOutboxStore {
        fn new(
            inner: Arc<SqliteSecurityStateStore>,
            mode: AdmissionPreparedFailureMode,
        ) -> Self {
            Self {
                inner,
                fail_next_admission_prepared: AtomicBool::new(true),
                mode,
            }
        }
    }

    impl AttestedFindingResponseOutboxStore for FailingAdmissionPreparedOutboxStore {
        fn ensure_attested_finding_response_outbox_ready(&self) -> PortResult<()> {
            self.inner
                .ensure_attested_finding_response_outbox_ready()
        }

        fn publish_attested_finding_response_plan(
            &self,
            publication: &AttestedFindingResponsePlanPublication,
        ) -> PortResult<CreateOutcome> {
            self.inner
                .publish_attested_finding_response_plan(publication)
        }

        fn load_attested_finding_response_outbox(
            &self,
            key: &AttestedFindingResponseOutboxKey,
        ) -> PortResult<Option<AttestedFindingResponseOutboxRecord>> {
            self.inner.load_attested_finding_response_outbox(key)
        }

        fn scan_unplanned_attested_finding_responses(
            &self,
            now_unix_ms: u64,
            limit: u32,
        ) -> PortResult<Vec<AttestedFindingResponseOutboxRecord>> {
            self.inner
                .scan_unplanned_attested_finding_responses(now_unix_ms, limit)
        }

        fn scan_incomplete_attested_finding_responses(
            &self,
            now_unix_ms: u64,
            limit: u32,
        ) -> PortResult<Vec<AttestedFindingResponseOutboxRecord>> {
            self.inner
                .scan_incomplete_attested_finding_responses(now_unix_ms, limit)
        }

        fn transition_attested_finding_response_outbox(
            &self,
            current: &AttestedFindingResponseOutboxRecord,
            transition: AttestedFindingResponseOutboxTransition,
        ) -> PortResult<AttestedFindingResponseOutboxRecord> {
            let inject_failure = matches!(
                &transition,
                AttestedFindingResponseOutboxTransition::AdmissionPrepared { .. }
            ) && self
                .fail_next_admission_prepared
                .swap(false, Ordering::AcqRel);
            if inject_failure {
                match self.mode {
                    AdmissionPreparedFailureMode::BeforeWrite => {
                        return Err(PortError::unavailable());
                    }
                    AdmissionPreparedFailureMode::AfterWrite => {
                        self.inner.transition_attested_finding_response_outbox(
                            current,
                            transition,
                        )?;
                        return Err(PortError::unavailable());
                    }
                }
            }
            self.inner
                .transition_attested_finding_response_outbox(current, transition)
        }

        fn attested_finding_response_outbox_health(
            &self,
        ) -> PortResult<AttestedFindingResponseOutboxHealth> {
            self.inner.attested_finding_response_outbox_health()
        }
    }

    impl AttestedFindingResponseOutboxStore for RejectingGlobalScanOutboxStore {
        fn ensure_attested_finding_response_outbox_ready(&self) -> PortResult<()> {
            self.inner
                .ensure_attested_finding_response_outbox_ready()
        }

        fn publish_attested_finding_response_plan(
            &self,
            publication: &AttestedFindingResponsePlanPublication,
        ) -> PortResult<CreateOutcome> {
            self.inner
                .publish_attested_finding_response_plan(publication)
        }

        fn load_attested_finding_response_outbox(
            &self,
            key: &AttestedFindingResponseOutboxKey,
        ) -> PortResult<Option<AttestedFindingResponseOutboxRecord>> {
            self.inner.load_attested_finding_response_outbox(key)
        }

        fn scan_unplanned_attested_finding_responses(
            &self,
            _: u64,
            _: u32,
        ) -> PortResult<Vec<AttestedFindingResponseOutboxRecord>> {
            self.global_scan_called.store(true, Ordering::Release);
            Err(PortError::unavailable())
        }

        fn scan_incomplete_attested_finding_responses(
            &self,
            _: u64,
            _: u32,
        ) -> PortResult<Vec<AttestedFindingResponseOutboxRecord>> {
            self.global_scan_called.store(true, Ordering::Release);
            Err(PortError::unavailable())
        }

        fn transition_attested_finding_response_outbox(
            &self,
            current: &AttestedFindingResponseOutboxRecord,
            transition: AttestedFindingResponseOutboxTransition,
        ) -> PortResult<AttestedFindingResponseOutboxRecord> {
            self.inner
                .transition_attested_finding_response_outbox(current, transition)
        }

        fn attested_finding_response_outbox_health(
            &self,
        ) -> PortResult<AttestedFindingResponseOutboxHealth> {
            self.inner.attested_finding_response_outbox_health()
        }
    }
mod synchronous_batch_recovery_targets_its_batch_instead_of_the_global_backlog;

mod synchronous_batch_recovery_processes_every_binding_and_preserves_the_first_error;


    pub(super) fn recovery_outbox_key(
        publication: &AttestedFindingBatchPublication,
        ordinal: usize,
    ) -> AttestedFindingResponseOutboxKey {
        let binding = &publication.body.bindings.as_slice()[ordinal];
        AttestedFindingResponseOutboxKey {
            tenant_id: binding.tenant_id.clone(),
            action_id: binding.action_id.clone(),
        }
    }

    pub(super) fn prepared_binding_for_outbox(
        record: &AttestedFindingResponseOutboxRecord,
        dispatch_id: RecordId,
    ) -> PreparedActiveResponseDispatchBinding {
        let response_plan = &record
            .publication
            .as_ref()
            .unwrap_or_else(|| panic!("prepared binding publication missing"))
            .body
            .response_plan;
        PreparedAttestedFindingResponse::synthetic(dispatch_id)
            .durable_dispatch_binding(response_plan)
            .unwrap_or_else(|error| panic!("synthetic prepared binding: {error}"))
    }
mod durable_recovery_crosses_plan_artifact_prepare_and_completion_crash_boundaries;

mod admission_prepared_persistence_failure_cancels_before_pending_expiry;

mod admission_prepared_ack_loss_preserves_reservation_and_executes_once;

mod prepared_recovery_is_not_starved_by_sustained_fresh_ingress;

mod committed_dispatch_recovers_before_mutable_finding_policy_or_live_readiness;

mod operation_committed_dispatch_resumes_after_executor_readback_is_missing;

mod rewritten_prepared_binding_resume_failure_stays_outcome_unknown;

mod authoritative_never_committed_probe_closes_prepared_dispatch_terminally;

mod expired_prepared_dispatch_terminates_without_mutable_live_dependencies;

mod startup_drain_does_not_confuse_deferred_backlog_with_empty_due_scan;

mod startup_drain_fails_closed_at_the_record_backlog_limit;

mod planner_api_accepts_only_authoritative_signed_finding_evidence;

mod prepared_crash_is_recovered_exactly_once_with_two_workers;








    mod authority_boundaries;






