#![cfg(feature = "std")]

use chio_security_types::ports::*;

struct FakePorts;

macro_rules! unavailable {
    () => {
        Err(PortError::new(
            PortErrorKind::Unavailable,
            ErrorCode::new("injected.unavailable")?,
        ))
    };
}

impl FlowStateStore for FakePorts {
    fn load(&self, _: &FlowStateKey) -> PortResult<Option<FlowStateSnapshot>> {
        unavailable!()
    }

    fn join(&self, _: &FlowJoinRequest) -> PortResult<FlowStateSnapshot> {
        unavailable!()
    }

    fn open_isolation_epoch(&self, _: &IsolationEpochTransition) -> PortResult<FlowStateSnapshot> {
        unavailable!()
    }

    fn acquire_egress_fence(&self, _: &EgressFenceRequest) -> PortResult<EgressFence> {
        unavailable!()
    }

    fn validate_egress_fence(&self, _: &EgressFence) -> PortResult<()> {
        unavailable!()
    }

    fn commit_egress_fence(&self, _: &EgressFenceCommit) -> PortResult<CommittedEgressFence> {
        unavailable!()
    }
}

impl IsolationEpochEvidenceVerifierPort for FakePorts {
    fn verify(&self, _: &IsolationEpochTransition) -> PortResult<VerifiedIsolationEvidence> {
        unavailable!()
    }
}

impl ClassificationPort for FakePorts {
    fn classify(&self, _: &ClassificationRequest) -> PortResult<ClassificationResult> {
        unavailable!()
    }
}

impl TripwireDetectorPort for FakePorts {
    fn detect(&self, _: &TripwireInput) -> PortResult<TripwireDecision> {
        unavailable!()
    }
}

impl DeclassificationUseStore for FakePorts {
    fn consume(&self, _: &DeclassificationConsumeRequest) -> PortResult<DeclassificationConsume> {
        unavailable!()
    }

    fn record_outcome(&self, _: &DeclassificationOutcomeRequest) -> PortResult<()> {
        unavailable!()
    }
}

impl SecurityEventVerifierPort for FakePorts {
    fn verify(&self, _: &UnverifiedSecurityEvent) -> PortResult<VerifiedSecurityEvent> {
        unavailable!()
    }
}

impl SecurityEventStore for FakePorts {
    fn append_verified(&self, _: &VerifiedSecurityEvent) -> PortResult<EventAppend> {
        unavailable!()
    }

    fn append_advisory(&self, _: &AdvisorySecurityEvent) -> PortResult<EventAppend> {
        unavailable!()
    }

    fn index_partition_event(&self, _: &CorrelationEventIndexRequest) -> PortResult<()> {
        unavailable!()
    }

    fn scan_partition(&self, _: &EventPartitionScan) -> PortResult<CorrelationScan> {
        unavailable!()
    }

    fn load_correlation(
        &self,
        _: &CorrelationPartitionKey,
    ) -> PortResult<Option<CorrelationPartial>> {
        unavailable!()
    }

    fn compare_and_swap_correlation(
        &self,
        _: &CorrelationCasRequest,
    ) -> PortResult<CorrelationPartial> {
        unavailable!()
    }

    fn delete_correlation(&self, _: &CorrelationDeleteRequest) -> PortResult<()> {
        unavailable!()
    }
}

impl SealedDecoyRegistryStore for FakePorts {
    fn load_by_id(&self, _: &DecoyArtifactLookup) -> PortResult<Option<SealedDecoyRecord>> {
        unavailable!()
    }

    fn load_by_marker(&self, _: &SealedMarkerLookup) -> PortResult<Option<SealedDecoyRecord>> {
        unavailable!()
    }

    fn load_by_public_ref(
        &self,
        _: &SealedPublicRefLookup,
    ) -> PortResult<Option<SealedDecoyRecord>> {
        unavailable!()
    }

    fn compare_and_swap(&self, _: &SealedDecoyCasRequest) -> PortResult<SealedDecoyRecord> {
        unavailable!()
    }

    fn scan(&self, _: &DecoyScan) -> PortResult<SealedDecoyPage> {
        unavailable!()
    }
}

impl ResponseStore for FakePorts {
    fn load_plan(&self, _: &ResponsePlanKey) -> PortResult<Option<ResponsePlanRecord>> {
        unavailable!()
    }

    fn create(&self, _: &ResponsePlanRecord) -> PortResult<CreateOutcome> {
        unavailable!()
    }

    fn compare_and_swap(&self, _: &ResponseCasRequest) -> PortResult<ResponsePlanRecord> {
        unavailable!()
    }

    fn load_effect(&self, _: &ResponseEffectKey) -> PortResult<Option<ResponseEffectRecord>> {
        unavailable!()
    }

    fn persist_effect(&self, _: &ResponseEffectRecord) -> PortResult<CreateOutcome> {
        unavailable!()
    }

    fn compare_and_swap_effect(
        &self,
        _: &ResponseEffectCasRequest,
    ) -> PortResult<ResponseEffectRecord> {
        unavailable!()
    }

    fn claim_due(&self, _: &SchedulerClaimRequest) -> PortResult<Vec<ScheduledWork>> {
        unavailable!()
    }
}

impl ResponseSchedulerStore for FakePorts {
    fn load_retry(&self, _: &SchedulerWorkKey) -> PortResult<Option<SchedulerRetryState>> {
        unavailable!()
    }

    fn validate_lease(&self, _: &ScheduledWork) -> PortResult<()> {
        unavailable!()
    }

    fn renew_lease(&self, _: &SchedulerLeaseRenewRequest) -> PortResult<ScheduledWork> {
        unavailable!()
    }

    fn record_retry(&self, _: &SchedulerRetryRequest) -> PortResult<SchedulerRetryState> {
        unavailable!()
    }

    fn acknowledge_health_event(
        &self,
        _: &SchedulerHealthAckRequest,
    ) -> PortResult<SchedulerRetryState> {
        unavailable!()
    }

    fn release_lease(&self, _: &SchedulerLeaseReleaseRequest) -> PortResult<()> {
        unavailable!()
    }
}

impl SchedulerHealthPort for FakePorts {
    fn page_once(&self, _: &SchedulerHealthPageRequest) -> PortResult<()> {
        unavailable!()
    }
}

impl ContainmentOverlayStore for FakePorts {
    fn apply_contribution(&self, _: &OverlayApplyRequest) -> PortResult<OverlaySnapshot> {
        unavailable!()
    }

    fn remove_contribution(&self, _: &OverlayRemoveRequest) -> PortResult<OverlaySnapshot> {
        unavailable!()
    }

    fn load_effective(&self, _: &TenantScopedId) -> PortResult<Option<OverlaySnapshot>> {
        unavailable!()
    }
}

impl BlastRadiusPort for FakePorts {
    fn resolve(&self, _: &BlastRadiusRequest) -> PortResult<BlastRadiusResult> {
        unavailable!()
    }

    fn acquire_fence(&self, _: &LineageFenceRequest) -> PortResult<LineageFence> {
        unavailable!()
    }

    fn query_fence(&self, _: &TenantScopedId) -> PortResult<Option<LineageFence>> {
        unavailable!()
    }

    fn release_fence(&self, _: &LineageFenceRelease) -> PortResult<()> {
        unavailable!()
    }
}

impl LineageFenceStore for FakePorts {
    fn acquire(&self, _: &LineageFenceRequest) -> PortResult<LineageFence> {
        unavailable!()
    }

    fn query(&self, _: &TenantScopedId) -> PortResult<Option<LineageFence>> {
        unavailable!()
    }

    fn release(&self, _: &LineageFenceRelease) -> PortResult<()> {
        unavailable!()
    }
}

impl ApprovalVerifierPort for FakePorts {
    fn verify_and_reserve(&self, _: &ApprovalRequest) -> PortResult<ApprovalReservation> {
        unavailable!()
    }

    fn commit(&self, _: &ApprovalReservationMutation) -> PortResult<()> {
        unavailable!()
    }

    fn cancel(&self, _: &ApprovalReservationMutation) -> PortResult<()> {
        unavailable!()
    }
}

impl ApprovalReservationStore for FakePorts {
    fn reserve(&self, _: &ApprovalReservationCreate) -> PortResult<CreateOutcome> {
        unavailable!()
    }

    fn load_reservation(
        &self,
        _: &TenantScopedId,
    ) -> PortResult<Option<StoredApprovalReservation>> {
        unavailable!()
    }

    fn commit_reservation(&self, _: &ApprovalReservationMutation) -> PortResult<()> {
        unavailable!()
    }

    fn cancel_reservation(&self, _: &ApprovalReservationMutation) -> PortResult<()> {
        unavailable!()
    }
}

impl EffectPort for FakePorts {
    fn execute(&self, _: &EffectRequest) -> PortResult<EffectResult> {
        unavailable!()
    }

    fn load_result(&self, _: &EffectResultQuery) -> PortResult<EffectExecutionStatus> {
        unavailable!()
    }
}

impl SecurityReceiptSink for FakePorts {
    fn sign_and_append(&self, _: &ReceiptAppendRequest) -> PortResult<OpaqueReceiptRef> {
        unavailable!()
    }
}

impl SecurityAlertPort for FakePorts {
    fn page(&self, _: &SecurityAlert) -> PortResult<()> {
        unavailable!()
    }
}

fn assert_every_port<T>()
where
    T: FlowStateStore
        + IsolationEpochEvidenceVerifierPort
        + ClassificationPort
        + TripwireDetectorPort
        + DeclassificationUseStore
        + SecurityEventVerifierPort
        + SecurityEventStore
        + SealedDecoyRegistryStore
        + ResponseStore
        + ResponseSchedulerStore
        + SchedulerHealthPort
        + ContainmentOverlayStore
        + BlastRadiusPort
        + LineageFenceStore
        + ApprovalVerifierPort
        + ApprovalReservationStore
        + EffectPort
        + SecurityReceiptSink
        + SecurityAlertPort,
{
}

#[test]
fn one_fake_can_satisfy_every_port_contract() {
    assert_every_port::<FakePorts>();
}

#[test]
fn port_errors_preserve_the_failure_class() -> Result<(), IdError> {
    for kind in [
        PortErrorKind::Unavailable,
        PortErrorKind::Conflict,
        PortErrorKind::InvalidData,
        PortErrorKind::IntegrityFailure,
    ] {
        let error = PortError::new(kind, ErrorCode::new("injected.failure")?);
        assert_eq!(error.kind(), kind);
        assert_eq!(error.code().as_str(), "injected.failure");
    }
    Ok(())
}

#[test]
fn identifiers_reject_noncanonical_decoding() {
    assert!(serde_json::from_str::<TenantId>(r#"" tenant-a""#).is_err());
    assert!(serde_json::from_str::<TenantId>(r#""tenant-a\u0000""#).is_err());
    assert!(serde_json::from_str::<TenantId>("\"\"").is_err());
}

#[test]
fn bounded_collections_reject_excess_items() {
    type TwoItems = BoundedVec<u8, 2>;
    assert!(serde_json::from_str::<TwoItems>("[1,2]").is_ok());
    assert!(serde_json::from_str::<TwoItems>("[1,2,3]").is_err());
}

#[test]
fn canonical_bodies_enforce_the_protocol_byte_ceiling() {
    assert!(CanonicalBody::new(vec![0_u8; 1_048_576]).is_ok());
    assert_eq!(
        CanonicalBody::new(vec![0_u8; 1_048_577]),
        Err(BodyError::TooLarge)
    );
}

#[test]
fn strict_port_shapes_reject_unknown_fields() {
    let json = r#"{
        "tenant_id":"tenant-a",
        "request_id":"request-a",
        "payload":[],
        "payload_digest":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        "unexpected":true
    }"#;
    assert!(serde_json::from_str::<ClassificationRequest>(json).is_err());
}

#[test]
fn authoritative_record_sets_are_strictly_sorted_and_unique() {
    assert!(serde_json::from_str::<RecordIdSet>(r#"["a","b"]"#).is_ok());
    assert!(serde_json::from_str::<RecordIdSet>(r#"["b","a"]"#).is_err());
    assert!(serde_json::from_str::<RecordIdSet>(r#"["a","a"]"#).is_err());
}
