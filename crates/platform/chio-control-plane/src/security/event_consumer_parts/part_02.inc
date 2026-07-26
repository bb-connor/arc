#[cfg(test)]
mod tests {
    use super::{
        build_attested_finding_batch_publication, AttestedFindingBatchPlanner,
        AttestedFindingAdmissionArtifacts, AttestedFindingResponseCompletionProof,
        AttestedFindingDispatchCommittedResume, AttestedFindingPreDispatchReconstruction,
        AttestedFindingResponseCoordinator, AttestedFindingResponsePolicyPlanner,
        AttestedFindingResponsePolicySelection, AttestedFindingResponseRecoveryLimits,
        CorrelationAttestor, CorrelationPort, DurableAttestedFindingBatchPlanner,
        DurableCorrelationIngress, KernelAttestedFindingResponseCoordinator,
        KernelActiveResponseApprovalVerifier,
        NativeSecurityEventVerifier, PreparedAttestedFindingResponse,
        ProductionCorrelationConsumer,
        ReservedAttestedFindingResponsePlan,
        RuleCorrelationOutcome, SecurityEventReceiptProjection, SqliteTemporalCorrelationPort,
        TrustedSecurityEventProducer, TrustedSecurityEventReceiptProducer,
        VerifiedSecurityEventIngress,
        governed_approval_request_from_native,
        SECURITY_EVENT_RECEIPT_PROJECTION_VERSION,
    };
    use crate::security::{DurableActiveResponseExecutor, NativeSecurityReceiptSink};
    use chio_core::capability::governance::{
        GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
        GovernedResponseEffect, GovernedResponsePlanIntentBody, GovernedTransactionIntent,
        CHIO_ACTIVE_RESPONSE_SERVER_ID, CHIO_RESPONSE_PLAN_SCHEMA,
    };
    use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
    use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
    use chio_core::{canonical_json_bytes, Ed25519Backend, Keypair};
    use chio_core_types::receipt::body::{ChioReceipt, ChioReceiptBody};
    use chio_core_types::receipt::decision::ToolCallAction;
    use chio_core_types::receipt::kinds::{
        BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
    };
    use chio_core_types::receipt::security::{
        ActiveDefenseReceiptBody, CorrelatedFindingReceiptBody,
    };
    use chio_core_types::SignedSecurityEvent;
    use chio_kernel::admission_operation::{
        AdmissionOperationKind, AdmissionOperationState, AdmissionOperationStore,
        ReplayReservationState,
    };
    use chio_kernel::approval::ApprovalStore;
    use chio_kernel::threshold_approval::{
        authorization_capability_hash, ThresholdApprovalProposal,
        ThresholdApprovalProposalBody, ThresholdApprovalRequirement,
    };
    use chio_kernel::{
        ActiveResponseArtifactAuthorityAttestation, ActiveResponseArtifactAuthorityAttestationBody,
        ActiveResponseCommittedDispatch,
        ActiveResponseExecutionApproval, ActiveResponseExecutionEvidence,
        ActiveResponseExecutionRequest, ActiveResponseExecutorAuthority,
        ActiveResponseExecutorAuthorityIdentity, ActiveResponseExecutorError,
        ActiveResponseFindingAuthority, ActiveResponseFindingAuthorityError,
        ActiveResponsePolicyResolutionError, ActiveResponseRequirement,
        ActiveResponseAuthorizationRequest,
        ActiveResponseSubmissionProof, ActiveResponseSubmissionProofBody,
        AuthoritativeCorrelatedFindingEvidence, AutomaticActiveResponseDispatchFenceOutcome,
        ChioKernel, GovernedSecurityRuntimePublication, KernelConfig, KernelError,
        MemoryBudgetConfig, PreparedActiveResponseAdmission, SecurityDispatchOutcomeHandle,
        SecurityPreDispatchContext, SecurityPreDispatchHook,
        DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
        DEFAULT_MAX_STREAM_TOTAL_BYTES,
    };
    use chio_quarantine::{
        CorrelationOutcome, CorrelationPolicy, CorrelationStatus, RuleLimits, TemporalRule,
    };
    use chio_security_kernel::{SecurityClock, SecurityEventIngress};
    use chio_security_types::ports::{
        AdmissionArtifactRef, ApprovalVerifierPort, AttestedFindingBatchBinding,
        AttestedFindingBatchBindings,
        AttestedFindingBatchKey, AttestedFindingBatchPublication, AttestedFindingBatchStore,
        AttestedFindingResponseAdmissionState, AttestedFindingResponseCompletionOutcome,
        AttestedFindingResponseCompletionState, AttestedFindingResponseOutboxKey,
        AttestedFindingResponseOutboxHealth, AttestedFindingResponseOutboxRecord,
        AttestedFindingResponseOutboxStore, AttestedFindingResponseOutboxTransition,
        AttestedFindingResponsePlanPublication, AttestedFindingResponsePlanningState,
        AlertDeliveryQuery, AlertDeliveryStatus, CanonicalBody, CorrelationIngressStore,
        CreateOutcome, Digest32, EffectExecutionStatus, EffectOperation, EffectPort,
        EffectRequest, EffectResult, EffectResultQuery, ErrorCode, EventAppend, EventId,
        GovernedApprovalRequest, GovernedApprovalReservationMutation,
        IssuanceFreezeAdmissionQuery, LeaseOwnerId, OpaqueReceiptRef, PortError, PortErrorKind,
        PortResult, PreparedActiveResponseDispatchBinding, ProducerId, ProducerTrustClass, RecordId,
        RuleId, SecurityAlert, SecurityAlertPort, SecurityEventVerifierPort, SessionId, TenantId,
        UnverifiedEventBatch, UnverifiedSecurityEvent, VerifiedSecurityEvent,
    };
    use chio_security_types::{
        OperatorCapabilityBinding, ResponseApprovalRequirement, ResponseEffectKind,
        ResponseEffectSpec, ResponseTarget, SecurityEventBody, SecurityEventBodyInput,
        SecurityEventKind, SecuritySeverity, SecuritySubject,
    };
    use chio_store_sqlite::security_state::SqliteSecurityStateStore;
    use chio_store_sqlite::{
        SqliteAdmissionOperationStore, SqliteApprovalStore, SqliteBudgetStore,
        SqliteReceiptStore,
    };
    use rusqlite::Connection;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn rejected<T, E>(result: Result<T, E>, message: &str) -> E {
        match result {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
    }

    struct FixedClock(u64);

    impl SecurityClock for FixedClock {
        fn now_unix_ms(&self) -> PortResult<u64> {
            Ok(self.0)
        }
    }

    struct MutableClock(AtomicU64);

    impl MutableClock {
        fn new(now_unix_ms: u64) -> Self {
            Self(AtomicU64::new(now_unix_ms))
        }

        fn set(&self, now_unix_ms: u64) {
            self.0.store(now_unix_ms, Ordering::Release);
        }
    }

    impl SecurityClock for MutableClock {
        fn now_unix_ms(&self) -> PortResult<u64> {
            Ok(self.0.load(Ordering::Acquire))
        }
    }

    struct ToggleClock {
        ready: AtomicBool,
        now_unix_ms: u64,
    }

    impl SecurityClock for ToggleClock {
        fn now_unix_ms(&self) -> PortResult<u64> {
            if self.ready.load(Ordering::Acquire) {
                Ok(self.now_unix_ms)
            } else {
                Err(PortError::unavailable())
            }
        }
    }

    fn tenant() -> TenantId {
        TenantId::new("tenant-events").unwrap_or_else(|error| panic!("tenant id: {error}"))
    }

    fn record(value: &str) -> RecordId {
        RecordId::new(value).unwrap_or_else(|error| panic!("record id: {error}"))
    }

    fn checked_sqlite_count(value: i64, label: &str) -> u64 {
        match u64::try_from(value) {
            Ok(value) => value,
            Err(error) => panic!("{label} is outside the u64 range: {error}"),
        }
    }

    fn producer() -> ProducerId {
        ProducerId::new("detector-production")
            .unwrap_or_else(|error| panic!("producer id: {error}"))
    }

    fn receipt_producer() -> ProducerId {
        ProducerId::new("receipt-authority").unwrap_or_else(|error| panic!("producer id: {error}"))
    }

    fn signed_event(keypair: &Keypair) -> UnverifiedSecurityEvent {
        signed_event_kind("event-signed", SecurityEventKind::TripwireObservation, keypair)
    }

    fn signed_event_kind(
        event_id: &str,
        event_kind: SecurityEventKind,
        keypair: &Keypair,
    ) -> UnverifiedSecurityEvent {
        signed_event_kind_at(event_id, event_kind, 9_900, 10_000, keypair)
    }

    fn signed_event_kind_at(
        event_id: &str,
        event_kind: SecurityEventKind,
        event_time_unix_ms: u64,
        ingest_time_unix_ms: u64,
        keypair: &Keypair,
    ) -> UnverifiedSecurityEvent {
        let body = SecurityEventBody::new(SecurityEventBodyInput {
            event_id: EventId::new(event_id)
                .unwrap_or_else(|error| panic!("event id: {error}")),
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

    fn verifier(keypair: &Keypair) -> NativeSecurityEventVerifier {
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

    fn receipt_event(
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

    fn verifier_with_receipts(
        internal_keypair: &Keypair,
        receipt_keypair: &Keypair,
        clock: Arc<dyn SecurityClock>,
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

    #[test]
    fn verifier_accepts_configured_internal_and_receipt_backed_provenance() {
        let internal = Keypair::from_seed(&[75_u8; 32]);
        let receipt = Keypair::from_seed(&[76_u8; 32]);
        let verifier = verifier_with_receipts(&internal, &receipt, Arc::new(FixedClock(10_000)));

        let internal_verified = verifier
            .verify(&signed_event(&internal))
            .unwrap_or_else(|error| panic!("internal verification: {error}"));
        let receipt_verified = verifier
            .verify(&receipt_event(
                &receipt,
                ToolOrigin::ChioInternal,
                9_900,
                10_000,
            ))
            .unwrap_or_else(|error| panic!("receipt verification: {error}"));

        assert_eq!(
            internal_verified.trust_class,
            ProducerTrustClass::InternalDetector
        );
        assert_eq!(
            receipt_verified.trust_class,
            ProducerTrustClass::VerifiedReceipt
        );
    }

    #[test]
    fn receipt_provenance_rejects_tampered_external_and_untrusted_sources() {
        let internal = Keypair::from_seed(&[77_u8; 32]);
        let trusted = Keypair::from_seed(&[78_u8; 32]);
        let untrusted = Keypair::from_seed(&[79_u8; 32]);
        let verifier = verifier_with_receipts(&internal, &trusted, Arc::new(FixedClock(10_000)));

        let mut tampered = receipt_event(&trusted, ToolOrigin::ChioInternal, 9_900, 10_000);
        let mut receipt: ChioReceipt = serde_json::from_slice(tampered.source_evidence.as_bytes())
            .unwrap_or_else(|error| panic!("receipt decode: {error}"));
        receipt.capability_id = "external.security-event".to_string();
        tampered.source_evidence = CanonicalBody::new(
            canonical_json_bytes(&receipt)
                .unwrap_or_else(|error| panic!("tampered receipt: {error}")),
        )
        .unwrap_or_else(|error| panic!("tampered evidence: {error}"));

        assert!(verifier.verify(&tampered).is_err());
        assert!(verifier
            .verify(&receipt_event(
                &trusted,
                ToolOrigin::HostExecutedProviderReported,
                9_900,
                10_000,
            ))
            .is_err());
        assert!(verifier
            .verify(&receipt_event(
                &untrusted,
                ToolOrigin::ChioInternal,
                9_900,
                10_000,
            ))
            .is_err());
    }

    #[test]
    fn receipt_provenance_binds_tenant_projection_and_freshness() {
        let internal = Keypair::from_seed(&[80_u8; 32]);
        let receipt = Keypair::from_seed(&[81_u8; 32]);
        let verifier = verifier_with_receipts(&internal, &receipt, Arc::new(FixedClock(100_000)));
        let mut wrong_tenant = receipt_event(&receipt, ToolOrigin::ChioInternal, 99_900, 100_000);
        wrong_tenant.tenant_id =
            TenantId::new("other-tenant").unwrap_or_else(|error| panic!("tenant id: {error}"));

        assert!(verifier.verify(&wrong_tenant).is_err());
        assert!(verifier
            .verify(&receipt_event(
                &receipt,
                ToolOrigin::ChioInternal,
                10_000,
                10_000,
            ))
            .is_err());
    }

    #[test]
    fn corrupted_signed_event_evidence_is_rejected_before_correlation() {
        let keypair = Keypair::from_seed(&[71_u8; 32]);
        let verifier = verifier(&keypair);
        let mut event = signed_event(&keypair);
        let mut corrupted = event.source_evidence.as_bytes().to_vec();
        if let Some(last) = corrupted.last_mut() {
            *last ^= 1;
        }
        event.source_evidence = CanonicalBody::new(corrupted)
            .unwrap_or_else(|error| panic!("corrupted evidence body: {error}"));
        assert!(verifier.verify(&event).is_err());
    }

    #[test]
    fn otherwise_valid_event_from_untrusted_producer_is_rejected() {
        let trusted = Keypair::from_seed(&[72_u8; 32]);
        let untrusted = Keypair::from_seed(&[73_u8; 32]);
        let verifier = verifier(&trusted);
        assert!(verifier.verify(&signed_event(&untrusted)).is_err());
    }

    #[test]
    fn trusted_producer_signature_from_an_unconfigured_policy_is_rejected() {
        let keypair = Keypair::from_seed(&[72_u8; 32]);
        let verifier = verifier(&keypair);
        let mut event = signed_event(&keypair);
        let signed: SignedSecurityEvent = serde_json::from_slice(event.source_evidence.as_bytes())
            .unwrap_or_else(|error| panic!("decode signed event: {error}"));
        let mut body = signed.body().clone();
        body.policy_version = record("policy-v2");
        let canonical_body = canonical_json_bytes(&body)
            .unwrap_or_else(|error| panic!("canonical policy-v2 body: {error}"));
        let resigned =
            SignedSecurityEvent::sign_with_backend(body, &Ed25519Backend::new(keypair.clone()))
                .unwrap_or_else(|error| panic!("sign policy-v2 event: {error}"));
        event.canonical_body = CanonicalBody::new(canonical_body.clone())
            .unwrap_or_else(|error| panic!("policy-v2 body: {error}"));
        event.body_hash = Digest32::new(*chio_core::sha256(&canonical_body).as_bytes());
        event.source_evidence = CanonicalBody::new(
            canonical_json_bytes(&resigned)
                .unwrap_or_else(|error| panic!("canonical policy-v2 envelope: {error}")),
        )
        .unwrap_or_else(|error| panic!("policy-v2 envelope: {error}"));

        assert!(verifier.verify(&event).is_err());
    }

    #[test]
    fn corrupt_tripwire_signature_cannot_enter_verified_persistence_or_correlation() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("create security event directory: {error}"));
        let database_path = directory.path().join("tripwire-events.sqlite3");
        let store = Arc::new(
            SqliteSecurityStateStore::open(&database_path)
                .unwrap_or_else(|error| panic!("open security event store: {error}")),
        );
        let keypair = Keypair::from_seed(&[74_u8; 32]);
        let ingress =
            VerifiedSecurityEventIngress::new(Arc::new(verifier(&keypair)), Arc::clone(&store))
                .unwrap_or_else(|error| panic!("construct verified ingress: {error}"));
        let mut corrupted = signed_event(&keypair);
        let signed: SignedSecurityEvent =
            serde_json::from_slice(corrupted.source_evidence.as_bytes())
                .unwrap_or_else(|error| panic!("decode signed event: {error}"));
        let wrong_key = Keypair::from_seed(&[75_u8; 32]);
        let wrong_signature = wrong_key.sign(
            &signed
                .signing_bytes()
                .unwrap_or_else(|error| panic!("security event signing bytes: {error}")),
        );
        let mut envelope = serde_json::to_value(&signed)
            .unwrap_or_else(|error| panic!("encode signed event: {error}"));
        envelope["signature"] = serde_json::to_value(wrong_signature)
            .unwrap_or_else(|error| panic!("encode corrupt signature: {error}"));
        let corrupt_envelope: SignedSecurityEvent = serde_json::from_value(envelope)
            .unwrap_or_else(|error| panic!("decode corrupt envelope: {error}"));
        corrupted.source_evidence = CanonicalBody::new(
            canonical_json_bytes(&corrupt_envelope)
                .unwrap_or_else(|error| panic!("canonical corrupt envelope: {error}")),
        )
        .unwrap_or_else(|error| panic!("bound corrupt envelope: {error}"));

        assert!(ingress.verify_and_append(&corrupted).is_err());

        let connection = Connection::open(&database_path)
            .unwrap_or_else(|error| panic!("inspect security event store: {error}"));
        let verified_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM security_verified_events", [], |row| {
                row.get(0)
            })
            .unwrap_or_else(|error| panic!("count verified events: {error}"));
        let verified_count = checked_sqlite_count(verified_count, "verified event count");
        let correlation_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM security_correlation_events",
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|error| panic!("count correlated events: {error}"));
        let correlation_count = checked_sqlite_count(correlation_count, "correlation event count");
        assert_eq!(verified_count, 0);
        assert_eq!(correlation_count, 0);

        assert_eq!(
            ingress
                .verify_and_append(&signed_event(&keypair))
                .unwrap_or_else(|error| panic!("ingest valid signed event: {error}")),
            EventAppend::Inserted
        );
        let verified_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM security_verified_events", [], |row| {
                row.get(0)
            })
            .unwrap_or_else(|error| panic!("recount verified events: {error}"));
        let verified_count = checked_sqlite_count(verified_count, "verified event recount");
        assert_eq!(verified_count, 1);
    }

    #[derive(Default)]
    struct RecordingPlanner {
        batches: Mutex<Vec<AttestedFindingBatchPublication>>,
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

    struct TwoOutcomeCorrelation;

    impl CorrelationPort for TwoOutcomeCorrelation {
        fn ensure_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn accepts_policy(&self, _: &RecordId) -> bool {
            true
        }

        fn correlate(
            &self,
            _: &chio_security_types::ports::VerifiedSecurityEvent,
            _: u64,
        ) -> PortResult<Vec<RuleCorrelationOutcome>> {
            Ok(["rule-one", "rule-two"]
                .into_iter()
                .map(|rule| RuleCorrelationOutcome {
                    rule_id: RuleId::new(rule).unwrap_or_else(|error| panic!("rule id: {error}")),
                    outcome: CorrelationOutcome {
                        status: CorrelationStatus::Matched,
                        findings: Vec::new(),
                        detector_health: Vec::new(),
                        automatic_response_suppressed: false,
                        watermark_unix_ms: 10_000,
                    },
                })
                .collect())
        }
    }

    struct ToggleCorrelation {
        ready: Arc<AtomicBool>,
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
            _: &chio_security_types::ports::VerifiedSecurityEvent,
            _: u64,
        ) -> PortResult<Vec<RuleCorrelationOutcome>> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn consumer_readiness_rechecks_verifier_clock_and_correlation_store() {
        let keypair = Keypair::from_seed(&[82_u8; 32]);
        let clock = Arc::new(ToggleClock {
            ready: AtomicBool::new(true),
            now_unix_ms: 10_000,
        });
        let verifier = Arc::new(
            NativeSecurityEventVerifier::new(
                Arc::clone(&clock) as Arc<dyn SecurityClock>,
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
            .unwrap_or_else(|error| panic!("verifier: {error}")),
        );
        let correlation_ready = Arc::new(AtomicBool::new(true));
        let consumer = ProductionCorrelationConsumer::from_parts(
            verifier,
            Arc::new(ToggleCorrelation {
                ready: Arc::clone(&correlation_ready),
            }),
            Arc::new(FailSecondAttestation {
                calls: Mutex::new(0),
            }),
            Arc::new(RecordingPlanner::default()),
        )
        .unwrap_or_else(|error| panic!("consumer: {error}"));

        clock.ready.store(false, Ordering::Release);
        assert!(consumer.ensure_ready().is_err());
        clock.ready.store(true, Ordering::Release);
        correlation_ready.store(false, Ordering::Release);
        assert!(consumer.ensure_ready().is_err());
    }

    fn authoritative_finding_with_identity(
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

    fn authoritative_finding() -> AuthoritativeCorrelatedFindingEvidence {
        authoritative_finding_with_identity("finding-first", "rule-one", 32)
    }

    fn reverse_lexicographic_findings() -> Vec<AuthoritativeCorrelatedFindingEvidence> {
        let mut findings = vec![
            authoritative_finding_with_identity("finding-order-a", "rule-one", 41),
            authoritative_finding_with_identity("finding-order-b", "rule-one", 51),
        ];
        findings.sort_by(|left, right| left.evidence_id().cmp(right.evidence_id()));
        findings.reverse();
        findings
    }

    struct TestFindingAuthority {
        findings: BTreeMap<OpaqueReceiptRef, AuthoritativeCorrelatedFindingEvidence>,
    }

    impl TestFindingAuthority {
        fn new(findings: &[AuthoritativeCorrelatedFindingEvidence]) -> Self {
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

    fn response_policy_selection() -> AttestedFindingResponsePolicySelection {
        let canonical_contribution = CanonicalBody::new(b"{\"maximum_invocations\":1}".to_vec())
            .unwrap_or_else(|error| panic!("policy contribution: {error}"));
        let contribution_hash =
            Digest32::new(*chio_core::sha256(canonical_contribution.as_bytes()).as_bytes());
        AttestedFindingResponsePolicySelection {
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

    struct RecordingResponsePolicy;

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
            Ok(AttestedFindingAdmissionArtifacts::synthetic(Digest32::new([
                74_u8; 32
            ])))
        }

    }

    #[derive(Default)]
    struct RecordingResponseCoordinator {
        executions: Mutex<Vec<(String, String)>>,
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
            Ok(AttestedFindingPreDispatchReconstruction::Prepared(Box::new(
                prepared,
            )))
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
    struct ArtifactEnforcingCoordinator {
        effects_applied: AtomicBool,
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
            Ok(AttestedFindingPreDispatchReconstruction::Prepared(Box::new(
                prepared,
            )))
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

    struct MissingArtifactResponsePolicy;

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

    struct SelectiveArtifactResponsePolicy {
        rejected: BTreeMap<OpaqueReceiptRef, ErrorCode>,
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
            Ok(AttestedFindingAdmissionArtifacts::synthetic(Digest32::new([
                74_u8; 32
            ])))
        }
    }

    struct OneFindingCorrelation;

    impl CorrelationPort for OneFindingCorrelation {
        fn ensure_ready(&self) -> PortResult<()> {
            Ok(())
        }

        fn accepts_policy(&self, _: &RecordId) -> bool {
            true
        }

        fn correlate(
            &self,
            _: &chio_security_types::ports::VerifiedSecurityEvent,
            _: u64,
        ) -> PortResult<Vec<RuleCorrelationOutcome>> {
            Ok(vec![RuleCorrelationOutcome {
                rule_id: RuleId::new("rule-one").unwrap_or_else(|error| panic!("rule id: {error}")),
                outcome: CorrelationOutcome {
                    status: CorrelationStatus::Matched,
                    findings: Vec::new(),
                    detector_health: Vec::new(),
                    automatic_response_suppressed: false,
                    watermark_unix_ms: 10_000,
                },
            }])
        }
    }

    struct OneFindingAttestor;

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

    struct FailOnceAttestor {
        fail: AtomicBool,
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

    struct AckLossCorrelationIngressStore {
        inner: Arc<SqliteSecurityStateStore>,
        lose_ack: AtomicBool,
    }

    impl CorrelationIngressStore for AckLossCorrelationIngressStore {
        fn ensure_correlation_ingress_ready(&self) -> PortResult<()> {
            self.inner.ensure_correlation_ingress_ready()
        }

        fn enqueue_verified_correlation_event(
            &self,
            event: &UnverifiedSecurityEvent,
            verified: &VerifiedSecurityEvent,
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
            verified: &VerifiedSecurityEvent,
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

    struct AckLossAttestedFindingBatchPlanner {
        inner: Arc<dyn AttestedFindingBatchPlanner>,
        lose_publish_ack: AtomicBool,
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

    fn correlation_consumer(
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

    fn native_tripwire_rule() -> TemporalRule {
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

    fn native_correlation_policy() -> CorrelationPolicy {
        CorrelationPolicy::new(0, 4_096, 8, false)
            .unwrap_or_else(|error| panic!("native correlation policy: {error}"))
    }

    #[test]
    fn idle_watermark_finalizes_a_single_tail_event_without_a_later_event() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = directory.path().join("idle-tail-correlation.sqlite");
        let store = Arc::new(
            SqliteSecurityStateStore::open(&path)
                .unwrap_or_else(|error| panic!("open ingress store: {error}")),
        );
        let keypair = Keypair::from_seed(&[98_u8; 32]);
        let event = signed_event_kind(
            "native-idle-tail",
            SecurityEventKind::CanaryInvocation,
            &keypair,
        );
        let clock = Arc::new(MutableClock::new(10_000));
        let event_verifier = Arc::new(
            NativeSecurityEventVerifier::new(
                Arc::clone(&clock) as Arc<dyn SecurityClock>,
                vec![TrustedSecurityEventProducer {
                    tenant_id: tenant(),
                    producer_id: producer(),
                    producer_key_id: record("detector-key-v1"),
                    policy_version: record("policy-v1"),
                    producer_key: keypair.public_key(),
                }],
                Vec::new(),
                60_000,
                200,
            )
            .unwrap_or_else(|error| panic!("verifier: {error}")),
        );
        let ingress = VerifiedSecurityEventIngress::new(
            Arc::clone(&event_verifier),
            Arc::clone(&store),
        )
        .unwrap_or_else(|error| panic!("ingress: {error}"));
        ingress
            .verify_and_append(&event)
            .unwrap_or_else(|error| panic!("enqueue tail event: {error}"));

        let correlation = Arc::new(
            SqliteTemporalCorrelationPort::new(
                Arc::clone(&store),
                CorrelationPolicy::new(200, 4_096, 8, false)
                    .unwrap_or_else(|error| panic!("correlation policy: {error}")),
                vec![native_tripwire_rule()],
            )
            .unwrap_or_else(|error| panic!("correlation port: {error}")),
        );
        let planner = durable_test_planner(&store);
        let consumer = Arc::new(
            ProductionCorrelationConsumer::from_parts(
                event_verifier,
                correlation,
                Arc::new(OneFindingAttestor),
                Arc::clone(&planner) as Arc<dyn AttestedFindingBatchPlanner>,
            )
            .unwrap_or_else(|error| panic!("consumer: {error}")),
        );
        let ingress_store: Arc<dyn CorrelationIngressStore> = store.clone();
        let drainer = DurableCorrelationIngress::new(ingress_store, consumer)
            .unwrap_or_else(|error| panic!("durable ingress drainer: {error}"));

        assert_eq!(
            drainer
                .drain_once(16)
                .unwrap_or_else(|error| panic!("defer tail event: {error}")),
            0
        );
        assert_eq!(
            store
                .count_pending_correlation_events()
                .unwrap_or_else(|error| panic!("pending deferred tail: {error}")),
            1
        );
        let connection = Connection::open(&path)
            .unwrap_or_else(|error| panic!("inspect deferred tail: {error}"));
        let deferred_outcomes: i64 = connection
            .query_row("SELECT COUNT(*) FROM security_correlation_outcomes", [], |row| {
                row.get(0)
            })
            .unwrap_or_else(|error| panic!("count deferred outcomes: {error}"));
        assert_eq!(deferred_outcomes, 0);

        clock.set(10_100);
        assert_eq!(
            drainer
                .drain_once(16)
                .unwrap_or_else(|error| panic!("flush idle tail: {error}")),
            1
        );
        assert_eq!(
            store
                .count_pending_correlation_events()
                .unwrap_or_else(|error| panic!("pending after idle flush: {error}")),
            0
        );
        for table in [
            "security_correlation_outcomes",
            "security_attested_finding_batches",
            "security_attested_finding_response_outbox",
        ] {
            let count: i64 = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))
                .unwrap_or_else(|error| panic!("count {table}: {error}"));
            assert_eq!(count, 1, "idle flush did not commit exactly one {table} row");
        }
    }

    #[test]
    fn future_fifo_prefix_does_not_starve_a_later_due_event() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = directory.path().join("future-prefix-correlation.sqlite");
        let store = Arc::new(
            SqliteSecurityStateStore::open(&path)
                .unwrap_or_else(|error| panic!("open ingress store: {error}")),
        );
        let keypair = Keypair::from_seed(&[100_u8; 32]);
        let future = signed_event_kind_at(
            "native-future-prefix",
            SecurityEventKind::CanaryInvocation,
            100_000,
            100_000,
            &keypair,
        );
        let due = signed_event_kind_at(
            "native-due-behind-prefix",
            SecurityEventKind::CanaryInvocation,
            40_000,
            100_000,
            &keypair,
        );
        let clock = Arc::new(MutableClock::new(100_000));
        let event_verifier = Arc::new(
            NativeSecurityEventVerifier::new(
                Arc::clone(&clock) as Arc<dyn SecurityClock>,
                vec![TrustedSecurityEventProducer {
                    tenant_id: tenant(),
                    producer_id: producer(),
                    producer_key_id: record("detector-key-v1"),
                    policy_version: record("policy-v1"),
                    producer_key: keypair.public_key(),
                }],
                Vec::new(),
                120_000,
                50_000,
            )
            .unwrap_or_else(|error| panic!("verifier: {error}")),
        );
        let ingress = VerifiedSecurityEventIngress::new(
            Arc::clone(&event_verifier),
            Arc::clone(&store),
        )
        .unwrap_or_else(|error| panic!("ingress: {error}"));
        ingress
            .verify_and_append(&future)
            .unwrap_or_else(|error| panic!("enqueue future prefix: {error}"));
        ingress
            .verify_and_append(&due)
            .unwrap_or_else(|error| panic!("enqueue due event: {error}"));

        let correlation = Arc::new(
            SqliteTemporalCorrelationPort::new(
                Arc::clone(&store),
                CorrelationPolicy::new(50_000, 4_096, 8, false)
                    .unwrap_or_else(|error| panic!("correlation policy: {error}")),
                vec![native_tripwire_rule()],
            )
            .unwrap_or_else(|error| panic!("correlation port: {error}")),
        );
        let planner = durable_test_planner(&store);
        let consumer = Arc::new(
            ProductionCorrelationConsumer::from_parts(
                event_verifier,
                correlation,
                Arc::new(OneFindingAttestor),
                Arc::clone(&planner) as Arc<dyn AttestedFindingBatchPlanner>,
            )
            .unwrap_or_else(|error| panic!("consumer: {error}")),
        );
        let ingress_store: Arc<dyn CorrelationIngressStore> = store.clone();
        let drainer = DurableCorrelationIngress::new(ingress_store, consumer)
            .unwrap_or_else(|error| panic!("durable ingress drainer: {error}"));

        assert_eq!(
            drainer
                .drain_once(1)
                .unwrap_or_else(|error| panic!("drain due event: {error}")),
            1
        );
        let pending = store
            .load_pending_correlation_events(1)
            .unwrap_or_else(|error| panic!("load remaining future event: {error}"));
        assert_eq!(pending.as_slice(), std::slice::from_ref(&future));
    }

    fn durable_test_planner(
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

    #[test]
    fn committed_correlation_outcome_survives_crash_before_attestation_and_reaches_outbox_once() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = directory.path().join("correlation-outcome-crash.sqlite");
        let keypair = Keypair::from_seed(&[95_u8; 32]);
        let event = signed_event_kind(
            "native-correlation-outcome-crash",
            SecurityEventKind::CanaryInvocation,
            &keypair,
        );
        let rule = native_tripwire_rule();

        {
            let store = Arc::new(
                SqliteSecurityStateStore::open(&path)
                    .unwrap_or_else(|error| panic!("open ingress store: {error}")),
            );
            let event_verifier = Arc::new(verifier(&keypair));
            let ingress = VerifiedSecurityEventIngress::new(
                Arc::clone(&event_verifier),
                Arc::clone(&store),
            )
            .unwrap_or_else(|error| panic!("ingress: {error}"));
            ingress
                .verify_and_append(&event)
                .unwrap_or_else(|error| panic!("enqueue native event: {error}"));
            let verified = event_verifier
                .verify(&event)
                .unwrap_or_else(|error| panic!("verify correlation event: {error}"));
            let correlation = SqliteTemporalCorrelationPort::new(
                Arc::clone(&store),
                native_correlation_policy(),
                vec![rule.clone()],
            )
            .unwrap_or_else(|error| panic!("correlation port: {error}"));
            let outcomes = correlation
                .correlate(&verified, 10_000)
                .unwrap_or_else(|error| panic!("commit correlation outcome: {error}"));
            assert_eq!(outcomes.len(), 1);
            assert_eq!(outcomes[0].outcome.status, CorrelationStatus::Matched);
            assert_eq!(outcomes[0].outcome.findings.len(), 1);
            assert_eq!(
                store
                    .count_pending_correlation_events()
                    .unwrap_or_else(|error| panic!("pending before crash: {error}")),
                1
            );
        }

        let store = Arc::new(
            SqliteSecurityStateStore::open(&path)
                .unwrap_or_else(|error| panic!("reopen after correlation crash: {error}")),
        );
        let correlation = Arc::new(
            SqliteTemporalCorrelationPort::new(
                Arc::clone(&store),
                native_correlation_policy(),
                vec![rule],
            )
            .unwrap_or_else(|error| panic!("recovered correlation port: {error}")),
        );
        let planner = durable_test_planner(&store);
        let consumer = Arc::new(
            ProductionCorrelationConsumer::from_parts(
                Arc::new(verifier(&keypair)),
                correlation,
                Arc::new(OneFindingAttestor),
                Arc::clone(&planner) as Arc<dyn AttestedFindingBatchPlanner>,
            )
            .unwrap_or_else(|error| panic!("recovered consumer: {error}")),
        );
        let ingress_store: Arc<dyn CorrelationIngressStore> = store.clone();
        let drainer = DurableCorrelationIngress::new(ingress_store, consumer)
            .unwrap_or_else(|error| panic!("durable ingress drainer: {error}"));
        assert_eq!(
            drainer
                .drain_once(16)
                .unwrap_or_else(|error| panic!("recover committed outcome: {error}")),
            1
        );

        let connection = Connection::open(&path)
            .unwrap_or_else(|error| panic!("inspect recovered pipeline: {error}"));
        for (table, expected) in [
            ("security_correlation_outcomes", 1_i64),
            ("security_attested_finding_batches", 1_i64),
            ("security_attested_finding_response_outbox", 1_i64),
        ] {
            let count: i64 = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))
                .unwrap_or_else(|error| panic!("count {table}: {error}"));
            assert_eq!(count, expected, "unexpected durable row count for {table}");
        }
        assert_eq!(
            store
                .count_pending_correlation_events()
                .unwrap_or_else(|error| panic!("pending after recovery: {error}")),
            0
        );
        assert_eq!(
            drainer
                .drain_once(16)
                .unwrap_or_else(|error| panic!("replay committed outcome: {error}")),
            0
        );
    }

    #[test]
    fn native_tripwire_ingress_recovers_and_persists_response_work_for_every_event_class() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let keypair = Keypair::from_seed(&[93_u8; 32]);
        for (event_id, event_kind) in [
            ("native-canary-ingress", SecurityEventKind::CanaryInvocation),
            ("native-honey-ingress", SecurityEventKind::TripwireObservation),
            (
                "native-watermark-ingress",
                SecurityEventKind::WatermarkObservation,
            ),
        ] {
            let path = directory.path().join(format!("{event_id}.sqlite"));
            let event = signed_event_kind(event_id, event_kind, &keypair);
            {
                let store = Arc::new(
                    SqliteSecurityStateStore::open(&path)
                        .unwrap_or_else(|error| panic!("open ingress store: {error}")),
                );
                let ingress = VerifiedSecurityEventIngress::new(
                    Arc::new(verifier(&keypair)),
                    Arc::clone(&store),
                )
                .unwrap_or_else(|error| panic!("ingress: {error}"));
                assert_eq!(
                    ingress
                        .verify_and_append(&event)
                        .unwrap_or_else(|error| panic!("enqueue native event: {error}")),
                    EventAppend::Inserted
                );
                assert_eq!(
                    store
                        .count_pending_correlation_events()
                        .unwrap_or_else(|error| panic!("pending ingress: {error}")),
                    1
                );
            }

            let store = Arc::new(
                SqliteSecurityStateStore::open(&path)
                    .unwrap_or_else(|error| panic!("reopen after ingress crash: {error}")),
            );
            let finding = authoritative_finding();
            let planner = Arc::new(
                DurableAttestedFindingBatchPlanner::new(
                    Arc::clone(&store) as Arc<dyn AttestedFindingBatchStore>,
                    Arc::clone(&store) as Arc<dyn AttestedFindingResponseOutboxStore>,
                    Arc::new(TestFindingAuthority::new(std::slice::from_ref(&finding))),
                    Arc::new(RecordingResponsePolicy),
                    Arc::new(RecordingResponseCoordinator::default()),
                    Arc::new(FixedClock(10_002)),
                )
                .unwrap_or_else(|error| panic!("durable planner: {error}")),
            );
            let consumer = correlation_consumer(
                &keypair,
                Arc::clone(&planner) as Arc<dyn AttestedFindingBatchPlanner>,
            );
            let ingress_store: Arc<dyn CorrelationIngressStore> = store.clone();
            let drainer = DurableCorrelationIngress::new(ingress_store, consumer)
                .unwrap_or_else(|error| panic!("durable ingress drainer: {error}"));
            assert_eq!(
                drainer
                    .drain_once(16)
                    .unwrap_or_else(|error| panic!("recover native event: {error}")),
                1
            );
            assert_eq!(
                store
                    .count_pending_correlation_events()
                    .unwrap_or_else(|error| panic!("pending after recovery: {error}")),
                0
            );

            let connection = Connection::open(&path)
                .unwrap_or_else(|error| panic!("inspect native ingress state: {error}"));
            let finding_batches: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM security_attested_finding_batches",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or_else(|error| panic!("count finding batches: {error}"));
            let response_work: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM security_attested_finding_response_outbox",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or_else(|error| panic!("count response work: {error}"));
            assert_eq!(finding_batches, 1);
            assert_eq!(response_work, 1);

            let replay_ingress = VerifiedSecurityEventIngress::new(
                Arc::new(verifier(&keypair)),
                Arc::clone(&store),
            )
            .unwrap_or_else(|error| panic!("replay ingress: {error}"));
            assert_eq!(
                replay_ingress
                    .verify_and_append(&event)
                    .unwrap_or_else(|error| panic!("replay native event: {error}")),
                EventAppend::Duplicate
            );
            assert_eq!(
                store
                    .count_pending_correlation_events()
                    .unwrap_or_else(|error| panic!("pending after replay: {error}")),
                0
            );
        }
    }

    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/security/event_consumer_parts/part_02_temporal_ingress.inc"
    ));
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/security/event_consumer_parts/part_02_recovery.inc"
    ));
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/security/event_consumer_parts/part_05.inc"
    ));
}
