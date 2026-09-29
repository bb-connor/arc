use super::*;

pub type VerifiedEventBatch = BoundedVec<SecurityEventVerificationRecord, 4_096>;
pub type UnverifiedEventBatch = BoundedVec<UnverifiedSecurityEvent, 4_096>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProducerTrustClass {
    InternalDetector,
    VerifiedReceipt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnverifiedSecurityEvent {
    pub tenant_id: TenantId,
    pub event_id: EventId,
    pub producer_id: ProducerId,
    pub event_time_unix_ms: u64,
    pub received_at_unix_ms: u64,
    pub canonical_body: CanonicalBody,
    pub body_hash: Digest32,
    pub source_evidence: CanonicalBody,
}

/// A trusted verifier/store projection, not a cryptographic proof token.
/// Event ingress must call the composition-installed SecurityEventVerifierPort;
/// deserializing this record never substitutes for that call.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityEventVerificationRecord {
    pub tenant_id: TenantId,
    pub event_id: EventId,
    pub producer_id: ProducerId,
    pub trust_class: ProducerTrustClass,
    pub event_time_unix_ms: u64,
    pub received_at_unix_ms: u64,
    pub canonical_body: CanonicalBody,
    pub body_hash: Digest32,
    pub evidence_hash: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisorySecurityEvent {
    pub tenant_id: TenantId,
    pub event_id: EventId,
    pub producer_id: ProducerId,
    pub event_time_unix_ms: u64,
    pub canonical_body: CanonicalBody,
    pub body_hash: Digest32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventAppend {
    Inserted,
    Duplicate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventPartitionScan {
    pub tenant_id: TenantId,
    pub rule_id: RuleId,
    pub partition_hash: Digest32,
    pub after_event_time_unix_ms: Option<u64>,
    pub after_event_id: Option<EventId>,
    pub through_event_time_unix_ms: u64,
    pub max_results: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationEventIndexRequest {
    pub key: CorrelationPartitionKey,
    pub event_id: EventId,
    pub transition_id: RecordId,
}

/// One crash-atomic correlation ingress mutation.
///
/// The verified event, its per-rule partition ownership, and the optional
/// tenant-rule capacity reservation either all commit or all remain absent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationEventAdmissionRequest {
    pub event: SecurityEventVerificationRecord,
    pub index: CorrelationEventIndexRequest,
    pub capacity: Option<CorrelationCasRequest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationEventAdmission {
    pub append: EventAppend,
    pub capacity: Option<CorrelationPartial>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationPartitionKey {
    pub tenant_id: TenantId,
    pub rule_id: RuleId,
    pub partition_hash: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationPartial {
    pub key: CorrelationPartitionKey,
    pub generation: u64,
    pub watermark_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub canonical_body: CanonicalBody,
    pub body_hash: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationCasRequest {
    pub scan: EventPartitionScan,
    pub observed_partition_generation: u64,
    pub partial: CorrelationPartial,
    pub expected_generation: Option<u64>,
    pub transition_id: RecordId,
}

/// Tenant and rule scoped identity of one durable temporal-correlation result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationOutcomeKey {
    pub tenant_id: TenantId,
    pub rule_id: RuleId,
    pub event_id: EventId,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationOutcomeStatus {
    Accepted,
    AdvisoryOnly,
    Deferred,
    Duplicate,
    Irrelevant,
    Matched,
    Suppressed,
    TooLate,
}

/// Opaque canonical journal entry written atomically with the correlation CAS.
/// The concrete correlator owns the body schema; the store enforces its exact
/// key, partition, final status, source-event, rule-version, and digest bindings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationOutcomePublication {
    pub key: CorrelationOutcomeKey,
    pub partition_hash: Digest32,
    pub status: CorrelationOutcomeStatus,
    pub watermark_unix_ms: u64,
    pub rule_version_hash: Digest32,
    pub event_body_hash: Digest32,
    pub event_evidence_hash: Digest32,
    pub canonical_body: CanonicalBody,
    pub body_hash: Digest32,
}

/// One crash-atomic partition transition and replayable outcome publication.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationOutcomeCommitRequest {
    pub correlation: CorrelationCasRequest,
    pub outcome: CorrelationOutcomePublication,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationScan {
    pub events: VerifiedEventBatch,
    pub partition_generation: u64,
    pub truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationDeleteRequest {
    pub key: CorrelationPartitionKey,
    pub expected_generation: u64,
    pub transition_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreateOutcome {
    Created,
    Existing,
}

#[cfg(feature = "std")]
pub trait SecurityEventVerifierPort: Send + Sync {
    fn verify(
        &self,
        event: &UnverifiedSecurityEvent,
    ) -> PortResult<SecurityEventVerificationRecord>;
}

#[cfg(feature = "std")]
pub trait SecurityEventStore: Send + Sync {
    fn admit_verified_correlation_event(
        &self,
        request: &CorrelationEventAdmissionRequest,
    ) -> PortResult<CorrelationEventAdmission>;
    fn append_verified(&self, event: &SecurityEventVerificationRecord) -> PortResult<EventAppend>;
    fn append_advisory(&self, event: &AdvisorySecurityEvent) -> PortResult<EventAppend>;
    fn index_partition_event(&self, request: &CorrelationEventIndexRequest) -> PortResult<()>;
    fn scan_partition(&self, scan: &EventPartitionScan) -> PortResult<CorrelationScan>;
    fn load_correlation(
        &self,
        key: &CorrelationPartitionKey,
    ) -> PortResult<Option<CorrelationPartial>>;
    /// Returns the greatest event time durably indexed for this partition.
    /// Correlators use this as the authoritative max-seen source even before
    /// the next partition-state transition commits.
    fn load_correlation_max_seen_event_time(
        &self,
        key: &CorrelationPartitionKey,
    ) -> PortResult<Option<u64>>;
    fn compare_and_swap_correlation(
        &self,
        request: &CorrelationCasRequest,
    ) -> PortResult<CorrelationPartial>;
    fn commit_correlation_outcome(
        &self,
        request: &CorrelationOutcomeCommitRequest,
    ) -> PortResult<CorrelationPartial>;
    /// Publishes the final event-specific journal when an already committed
    /// partition transition covered this indexed event.
    fn commit_correlation_outcome_only(
        &self,
        outcome: &CorrelationOutcomePublication,
    ) -> PortResult<CreateOutcome>;
    fn load_correlation_outcome(
        &self,
        key: &CorrelationOutcomeKey,
    ) -> PortResult<Option<CorrelationOutcomePublication>>;
    fn delete_correlation(&self, request: &CorrelationDeleteRequest) -> PortResult<()>;
}

/// Durable handoff between authenticated event ingress and temporal
/// correlation.
///
/// Implementations must append `verified` and retain the exact unverified
/// envelope in one transaction. Acknowledgements are permanent tombstones:
/// replaying the same authenticated envelope after acknowledgement must not
/// make it pending again, while any identity rebinding must fail closed.
#[cfg(feature = "std")]
pub trait CorrelationIngressStore: Send + Sync {
    fn ensure_correlation_ingress_ready(&self) -> PortResult<()>;
    fn enqueue_verified_correlation_event(
        &self,
        event: &UnverifiedSecurityEvent,
        verified: &SecurityEventVerificationRecord,
    ) -> PortResult<EventAppend>;
    fn load_pending_correlation_events(&self, max_results: u32)
        -> PortResult<UnverifiedEventBatch>;
    fn validate_pending_correlation_event(
        &self,
        event: &UnverifiedSecurityEvent,
        verified: &SecurityEventVerificationRecord,
    ) -> PortResult<()>;
    fn acknowledge_correlated_event(&self, event: &UnverifiedSecurityEvent) -> PortResult<()>;
    fn count_pending_correlation_events(&self) -> PortResult<u64>;
}
