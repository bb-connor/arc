pub use crate::deception::{
    DecoyArtifactLookup, DecoyScan, SealedDecoyCasRequest, SealedDecoyPage, SealedDecoyRecord,
    SealedMarkerLookup, SealedPublicRefLookup, WatermarkObservation, WatermarkObservationResult,
    WatermarkSequenceReservation, WatermarkSequenceReservationResult,
};
use crate::InformationLabel;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

const MAX_ID_BYTES: usize = 256;
const MAX_CANONICAL_BODY_BYTES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PortErrorKind {
    Unavailable,
    Conflict,
    InvalidData,
    IntegrityFailure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortError {
    kind: PortErrorKind,
    code: ErrorCode,
}

impl PortError {
    #[must_use]
    pub const fn new(kind: PortErrorKind, code: ErrorCode) -> Self {
        Self { kind, code }
    }

    #[must_use]
    pub const fn kind(&self) -> PortErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn code(&self) -> &ErrorCode {
        &self.code
    }

    #[must_use]
    pub fn unavailable() -> Self {
        Self::new(
            PortErrorKind::Unavailable,
            ErrorCode("store.unavailable".to_string()),
        )
    }

    #[must_use]
    pub fn conflict() -> Self {
        Self::new(
            PortErrorKind::Conflict,
            ErrorCode("store.conflict".to_string()),
        )
    }

    #[must_use]
    pub fn invalid_data() -> Self {
        Self::new(
            PortErrorKind::InvalidData,
            ErrorCode("store.invalid_data".to_string()),
        )
    }

    #[must_use]
    pub fn integrity_failure() -> Self {
        Self::new(
            PortErrorKind::IntegrityFailure,
            ErrorCode("store.integrity_failure".to_string()),
        )
    }
}

impl fmt::Display for PortError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.kind, self.code)
    }
}

impl core::error::Error for PortError {}

pub type PortResult<T> = Result<T, PortError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdError {
    Blank,
    TooLong,
    NonCanonical,
}

impl fmt::Display for IdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Blank => "identifier is blank",
            Self::TooLong => "identifier exceeds the byte limit",
            Self::NonCanonical => "identifier is not canonical",
        };
        formatter.write_str(message)
    }
}

impl core::error::Error for IdError {}

impl From<IdError> for PortError {
    fn from(_: IdError) -> Self {
        Self::new(
            PortErrorKind::InvalidData,
            ErrorCode("invalid.identifier".to_string()),
        )
    }
}

fn validate_id(value: &str) -> Result<(), IdError> {
    if value.is_empty() {
        return Err(IdError::Blank);
    }
    if value.len() > MAX_ID_BYTES {
        return Err(IdError::TooLong);
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(IdError::NonCanonical);
    }
    Ok(())
}

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
                let value = value.into();
                validate_id(&value)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct IdVisitor;

                impl<'de> Visitor<'de> for IdVisitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str("a bounded canonical identifier")
                    }

                    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        validate_id(value).map_err(E::custom)?;
                        Ok($name(String::from(value)))
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        validate_id(value).map_err(E::custom)?;
                        Ok($name(String::from(value)))
                    }

                    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        validate_id(&value).map_err(E::custom)?;
                        Ok($name(value))
                    }
                }

                deserializer.deserialize_str(IdVisitor)
            }
        }
    };
}

id_type!(TenantId);
id_type!(RecordId);
id_type!(LineageId);
id_type!(SessionId);
id_type!(IsolationEpochId);
id_type!(RequestId);
id_type!(EventId);
id_type!(RuleId);
id_type!(ArtifactId);
id_type!(GrantId);
id_type!(ActionId);
id_type!(EffectId);
id_type!(LeaseOwnerId);
id_type!(ClassifierId);
id_type!(ClassifierVersion);
id_type!(ProducerId);
id_type!(PurposeId);
id_type!(DestinationId);
id_type!(ErrorCode);
id_type!(OpaqueReceiptRef);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest32([u8; 32]);

impl Digest32 {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct CanonicalBody(Vec<u8>);

impl CanonicalBody {
    pub fn new(bytes: Vec<u8>) -> Result<Self, BodyError> {
        if bytes.len() > MAX_CANONICAL_BODY_BYTES {
            return Err(BodyError::TooLarge);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyError {
    TooLarge,
}

impl fmt::Display for BodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("canonical body exceeds the byte limit")
    }
}

impl core::error::Error for BodyError {}

impl<'de> Deserialize<'de> for CanonicalBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BodyVisitor;

        impl<'de> Visitor<'de> for BodyVisitor {
            type Value = CanonicalBody;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded byte array")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let capacity = sequence
                    .size_hint()
                    .unwrap_or(0)
                    .min(MAX_CANONICAL_BODY_BYTES);
                let mut bytes = Vec::with_capacity(capacity);
                while let Some(byte) = sequence.next_element::<u8>()? {
                    if bytes.len() == MAX_CANONICAL_BODY_BYTES {
                        return Err(de::Error::custom("canonical body exceeds the byte limit"));
                    }
                    bytes.push(byte);
                }
                Ok(CanonicalBody(bytes))
            }
        }

        deserializer.deserialize_seq(BodyVisitor)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct BoundedVec<T, const MAX: usize>(Vec<T>);

impl<T, const MAX: usize> BoundedVec<T, MAX> {
    pub fn new(values: Vec<T>) -> Result<Self, CollectionError> {
        if values.len() > MAX {
            return Err(CollectionError::TooManyItems);
        }
        Ok(Self(values))
    }

    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        self.0.as_slice()
    }

    #[must_use]
    pub fn into_vec(self) -> Vec<T> {
        self.0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectionError {
    TooManyItems,
}

impl fmt::Display for CollectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("collection exceeds the item limit")
    }
}

impl core::error::Error for CollectionError {}

impl<'de, T, const MAX: usize> Deserialize<'de> for BoundedVec<T, MAX>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BoundedVisitor<T, const MAX: usize>(core::marker::PhantomData<T>);

        impl<'de, T, const MAX: usize> Visitor<'de> for BoundedVisitor<T, MAX>
        where
            T: Deserialize<'de>,
        {
            type Value = BoundedVec<T, MAX>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "an array with at most {MAX} items")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let capacity = sequence.size_hint().unwrap_or(0).min(MAX);
                let mut values = Vec::with_capacity(capacity);
                while let Some(value) = sequence.next_element::<T>()? {
                    if values.len() == MAX {
                        return Err(de::Error::custom("collection exceeds the item limit"));
                    }
                    values.push(value);
                }
                Ok(BoundedVec(values))
            }
        }

        deserializer.deserialize_seq(BoundedVisitor::<T, MAX>(core::marker::PhantomData))
    }
}

pub type ClassificationFindings = BoundedVec<ClassificationFinding, 256>;
pub type VerifiedEventBatch = BoundedVec<VerifiedSecurityEvent, 4_096>;
pub type OverlayContributions = BoundedVec<OverlayContribution, 256>;
pub type BlastRadiusSeeds = BoundedVec<RecordId, 256>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RecordIdSet(BoundedVec<RecordId, 4_096>);

impl RecordIdSet {
    pub fn new(values: Vec<RecordId>) -> Result<Self, RecordIdSetError> {
        if values.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(RecordIdSetError::NotStrictlySorted);
        }
        BoundedVec::new(values)
            .map(Self)
            .map_err(|_| RecordIdSetError::TooManyItems)
    }

    #[must_use]
    pub fn as_slice(&self) -> &[RecordId] {
        self.0.as_slice()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordIdSetError {
    TooManyItems,
    NotStrictlySorted,
}

impl fmt::Display for RecordIdSetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyItems => formatter.write_str("record id set exceeds the item limit"),
            Self::NotStrictlySorted => {
                formatter.write_str("record ids are not strictly sorted and unique")
            }
        }
    }
}

impl core::error::Error for RecordIdSetError {}

impl<'de> Deserialize<'de> for RecordIdSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = BoundedVec::<RecordId, 4_096>::deserialize(deserializer)?.into_vec();
        Self::new(values).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantScopedId {
    pub tenant_id: TenantId,
    pub id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowStateKey {
    pub tenant_id: TenantId,
    pub principal_id: crate::PrincipalId,
    pub lineage_id: LineageId,
    pub session_id: SessionId,
    pub isolation_epoch_id: IsolationEpochId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowStateSnapshot {
    pub key: FlowStateKey,
    pub principal_label: InformationLabel,
    pub lineage_label: InformationLabel,
    pub session_label: InformationLabel,
    pub context_generation: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowJoinRequest {
    pub key: FlowStateKey,
    pub principal_join: InformationLabel,
    pub lineage_join: InformationLabel,
    pub session_join: InformationLabel,
    pub transition_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IsolationEpochTransition {
    pub tenant_id: TenantId,
    pub principal_id: crate::PrincipalId,
    pub lineage_id: LineageId,
    pub previous_isolation_epoch_id: IsolationEpochId,
    pub new_isolation_epoch_id: IsolationEpochId,
    pub new_session_id: SessionId,
    pub verification_evidence_hash: Digest32,
    pub transition_id: RecordId,
    pub effective_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedIsolationEvidence {
    pub verifier_id: RecordId,
    pub receipt_ref: OpaqueReceiptRef,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EgressFenceRequest {
    pub key: FlowStateKey,
    pub request_id: RequestId,
    pub request_hash: Digest32,
    pub expected_context_generation: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EgressFence {
    pub fence_id: RecordId,
    pub key: FlowStateKey,
    pub request_id: RequestId,
    pub request_hash: Digest32,
    pub context_generation: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EgressFenceCommit {
    pub fence: EgressFence,
    pub dispatch_commitment_id: RecordId,
    pub committed_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedEgressFence {
    pub fence_id: RecordId,
    pub request_id: RequestId,
    pub request_hash: Digest32,
    pub context_generation: u64,
    pub dispatch_commitment_id: RecordId,
    pub committed_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClassificationRequest {
    pub tenant_id: TenantId,
    pub request_id: RequestId,
    pub payload: CanonicalBody,
    pub payload_digest: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClassificationFinding {
    pub category: RecordId,
    pub confidence_basis_points: u16,
    pub byte_range: Option<ByteRange>,
    pub field_path: Option<RecordId>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClassificationResult {
    pub tenant_id: TenantId,
    pub request_id: RequestId,
    pub payload_digest: Digest32,
    pub classifier_id: ClassifierId,
    pub classifier_version: ClassifierVersion,
    pub findings: ClassificationFindings,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TripwireKind {
    CanaryCapability,
    HoneyTool,
    CredentialArtifact,
    FileMarker,
    BrowserCookie,
    InternalHostname,
    SignedWatermark,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TripwireInput {
    pub tenant_id: TenantId,
    pub request_id: RequestId,
    pub kind: TripwireKind,
    /// Bounded presented bytes. The detector verifies `content_digest`
    /// before interpreting this value.
    pub content: CanonicalBody,
    pub content_digest: Digest32,
    pub canonical_context_digest: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum TripwireDecision {
    Clear,
    Match {
        artifact_id_hash: Digest32,
        artifact_version_hash: Digest32,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationConsumeRequest {
    pub tenant_id: TenantId,
    pub grant_id: GrantId,
    pub request_hash: Digest32,
    pub consumed_at_unix_ms: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclassificationUseState {
    ConsumedPendingDispatch,
    Released,
    DispatchFailed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum DeclassificationConsume {
    Consumed,
    AlreadyConsumed {
        request_hash: Digest32,
        state: DeclassificationUseState,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationOutcomeRequest {
    pub tenant_id: TenantId,
    pub grant_id: GrantId,
    pub request_hash: Digest32,
    pub expected_state: DeclassificationUseState,
    pub new_state: DeclassificationUseState,
    pub transition_id: RecordId,
}

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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedSecurityEvent {
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponsePlanRecord {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub generation: u64,
    pub state: RecordId,
    pub canonical_body: CanonicalBody,
    pub body_hash: Digest32,
    pub due_at_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponsePlanKey {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseCasRequest {
    pub record: ResponsePlanRecord,
    pub expected_generation: u64,
    pub transition_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEffectRecord {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub effect_id: EffectId,
    pub generation: u64,
    pub scheduler_fencing_token: u64,
    pub state: RecordId,
    pub canonical_body: CanonicalBody,
    pub body_hash: Digest32,
    pub encrypted_rollback_ref: Option<RecordId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEffectKey {
    pub tenant_id: TenantId,
    pub effect_id: EffectId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEffectCasRequest {
    pub record: ResponseEffectRecord,
    pub expected_generation: u64,
    pub transition_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerClaimRequest {
    pub tenant_id: TenantId,
    pub claim_id: RecordId,
    pub lease_owner_id: LeaseOwnerId,
    pub now_unix_ms: u64,
    pub lease_expires_at_unix_ms: u64,
    pub max_claims: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduledWork {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub lease_owner_id: LeaseOwnerId,
    pub lease_expires_at_unix_ms: u64,
    pub fencing_token: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerWorkKey {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerRetryState {
    pub key: SchedulerWorkKey,
    pub attempts: u32,
    pub last_error: ErrorCode,
    pub first_failure_at_unix_ms: u64,
    pub not_before_unix_ms: u64,
    pub health_event_id: Option<RecordId>,
    pub health_event_delivered: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerLeaseRenewRequest {
    pub work: ScheduledWork,
    pub now_unix_ms: u64,
    pub lease_expires_at_unix_ms: u64,
    pub transition_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerRetryRequest {
    pub work: ScheduledWork,
    pub expected_attempts: u32,
    pub error_code: ErrorCode,
    pub first_failure_at_unix_ms: u64,
    pub now_unix_ms: u64,
    pub not_before_unix_ms: u64,
    pub health_event_id: Option<RecordId>,
    pub transition_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerHealthAckRequest {
    pub key: SchedulerWorkKey,
    pub event_id: RecordId,
    pub transition_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerLeaseReleaseRequest {
    pub work: ScheduledWork,
    pub clear_retry_state: bool,
    pub transition_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OverlayContribution {
    pub effect_id: EffectId,
    pub posture_rank: u32,
    pub contribution_hash: Digest32,
    pub expires_at_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OverlayApplyRequest {
    pub target: TenantScopedId,
    pub action_id: ActionId,
    pub contribution: OverlayContribution,
    pub expected_generation: u64,
    pub scheduler_fencing_token: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OverlayRemoveRequest {
    pub target: TenantScopedId,
    pub action_id: ActionId,
    pub effect_id: EffectId,
    pub expected_generation: u64,
    pub scheduler_fencing_token: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OverlaySnapshot {
    pub target: TenantScopedId,
    pub generation: u64,
    pub effective_posture_rank: u32,
    pub active_contributions: OverlayContributions,
    pub highest_fencing_token: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlastRadiusRequest {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub seed_ids: BlastRadiusSeeds,
    pub max_nodes: u32,
    pub max_edges: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "completeness")]
pub enum BlastRadiusResult {
    Exact {
        commit_index: u64,
        sorted_affected_ids: RecordIdSet,
        affected_set_hash: Digest32,
        graph_slice_hash: Digest32,
    },
    Incomplete {
        commit_index: u64,
        reason: ErrorCode,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LineageFenceRequest {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub expected_commit_index: u64,
    pub expected_affected_set_hash: Digest32,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LineageFence {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub commit_index: u64,
    pub affected_set_hash: Digest32,
    pub fencing_token: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LineageFenceRelease {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub fencing_token: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequest {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub operator_capability_digest: Digest32,
    pub proposal_digest: Digest32,
    pub intent_hash: Digest32,
    pub canonical_approval_set: CanonicalBody,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalReservation {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub reservation_id: RecordId,
    pub approval_set_hash: Digest32,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalReservationMutation {
    pub reservation: ApprovalReservation,
    pub transition_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalReservationCreate {
    pub reservation: ApprovalReservation,
    pub transition_id: RecordId,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalReservationState {
    Reserved,
    Committed,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredApprovalReservation {
    pub reservation: ApprovalReservation,
    pub state: ApprovalReservationState,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectOperation {
    Apply,
    Remove,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectRequest {
    pub tenant_id: TenantId,
    pub effect_id: EffectId,
    pub operation: EffectOperation,
    pub idempotency_key: RecordId,
    pub expected_version_hash: Digest32,
    pub scheduler_fencing_token: u64,
    pub canonical_contribution: CanonicalBody,
    pub contribution_hash: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectResult {
    pub effect_id: EffectId,
    pub resulting_version_hash: Digest32,
    pub applied: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectResultQuery {
    pub tenant_id: TenantId,
    pub effect_id: EffectId,
    pub operation: EffectOperation,
    pub idempotency_key: RecordId,
    pub expected_version_hash: Digest32,
    pub scheduler_fencing_token: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status", deny_unknown_fields)]
pub enum EffectExecutionStatus {
    NotExecuted,
    Completed { result: EffectResult },
    Failed { error_code: ErrorCode },
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptAppendRequest {
    pub tenant_id: TenantId,
    pub evidence_type: RecordId,
    pub canonical_body: CanonicalBody,
    pub body_hash: Digest32,
    pub transition_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityAlert {
    pub tenant_id: TenantId,
    pub alert_type: RecordId,
    pub finding_id_hash: Digest32,
    pub action_id_hash: Option<Digest32>,
    pub evidence_hash: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerHealthPageRequest {
    pub event_id: RecordId,
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub first_failure_at_unix_ms: u64,
    pub alert: SecurityAlert,
}

#[cfg(feature = "std")]
pub trait IsolationEpochEvidenceVerifierPort: Send + Sync {
    fn verify(
        &self,
        transition: &IsolationEpochTransition,
    ) -> PortResult<VerifiedIsolationEvidence>;
}

#[cfg(feature = "std")]
pub trait FlowStateStore: Send + Sync {
    fn load(&self, key: &FlowStateKey) -> PortResult<Option<FlowStateSnapshot>>;
    fn join(&self, request: &FlowJoinRequest) -> PortResult<FlowStateSnapshot>;
    fn open_isolation_epoch(
        &self,
        transition: &IsolationEpochTransition,
    ) -> PortResult<FlowStateSnapshot>;
    fn acquire_egress_fence(&self, request: &EgressFenceRequest) -> PortResult<EgressFence>;
    fn validate_egress_fence(&self, fence: &EgressFence) -> PortResult<()>;
    fn commit_egress_fence(
        &self,
        commitment: &EgressFenceCommit,
    ) -> PortResult<CommittedEgressFence>;
}

#[cfg(feature = "std")]
pub trait ClassificationPort: Send + Sync {
    fn classify(&self, request: &ClassificationRequest) -> PortResult<ClassificationResult>;
}

#[cfg(feature = "std")]
pub trait TripwireDetectorPort: Send + Sync {
    fn detect(&self, input: &TripwireInput) -> PortResult<TripwireDecision>;
}

#[cfg(feature = "std")]
pub trait DeclassificationUseStore: Send + Sync {
    fn consume(
        &self,
        request: &DeclassificationConsumeRequest,
    ) -> PortResult<DeclassificationConsume>;
    fn record_outcome(&self, request: &DeclassificationOutcomeRequest) -> PortResult<()>;
}

#[cfg(feature = "std")]
pub trait SecurityEventVerifierPort: Send + Sync {
    fn verify(&self, event: &UnverifiedSecurityEvent) -> PortResult<VerifiedSecurityEvent>;
}

#[cfg(feature = "std")]
pub trait SecurityEventStore: Send + Sync {
    fn append_verified(&self, event: &VerifiedSecurityEvent) -> PortResult<EventAppend>;
    fn append_advisory(&self, event: &AdvisorySecurityEvent) -> PortResult<EventAppend>;
    fn index_partition_event(&self, request: &CorrelationEventIndexRequest) -> PortResult<()>;
    fn scan_partition(&self, scan: &EventPartitionScan) -> PortResult<CorrelationScan>;
    fn load_correlation(
        &self,
        key: &CorrelationPartitionKey,
    ) -> PortResult<Option<CorrelationPartial>>;
    fn compare_and_swap_correlation(
        &self,
        request: &CorrelationCasRequest,
    ) -> PortResult<CorrelationPartial>;
    fn delete_correlation(&self, request: &CorrelationDeleteRequest) -> PortResult<()>;
}

#[cfg(feature = "std")]
pub trait SealedDecoyRegistryStore: Send + Sync {
    fn load_by_id(&self, id: &DecoyArtifactLookup) -> PortResult<Option<SealedDecoyRecord>>;
    fn load_by_marker(&self, lookup: &SealedMarkerLookup) -> PortResult<Option<SealedDecoyRecord>>;
    fn load_by_public_ref(
        &self,
        lookup: &SealedPublicRefLookup,
    ) -> PortResult<Option<SealedDecoyRecord>>;
    fn compare_and_swap(&self, request: &SealedDecoyCasRequest) -> PortResult<SealedDecoyRecord>;
    fn scan(&self, scan: &DecoyScan) -> PortResult<SealedDecoyPage>;
}

#[cfg(feature = "std")]
pub trait WatermarkSequenceStore: Send + Sync {
    fn reserve(
        &self,
        request: &WatermarkSequenceReservation,
    ) -> PortResult<WatermarkSequenceReservationResult>;
}

#[cfg(feature = "std")]
pub trait WatermarkObservationStore: Send + Sync {
    fn record_first(
        &self,
        observation: &WatermarkObservation,
    ) -> PortResult<WatermarkObservationResult>;
}

#[cfg(feature = "std")]
pub trait ResponseStore: Send + Sync {
    fn load_plan(&self, key: &ResponsePlanKey) -> PortResult<Option<ResponsePlanRecord>>;
    fn create(&self, record: &ResponsePlanRecord) -> PortResult<CreateOutcome>;
    fn compare_and_swap(&self, request: &ResponseCasRequest) -> PortResult<ResponsePlanRecord>;
    fn load_effect(&self, key: &ResponseEffectKey) -> PortResult<Option<ResponseEffectRecord>>;
    fn persist_effect(&self, record: &ResponseEffectRecord) -> PortResult<CreateOutcome>;
    fn compare_and_swap_effect(
        &self,
        request: &ResponseEffectCasRequest,
    ) -> PortResult<ResponseEffectRecord>;
    fn claim_due(&self, request: &SchedulerClaimRequest) -> PortResult<Vec<ScheduledWork>>;
}

#[cfg(feature = "std")]
pub trait ResponseSchedulerStore: ResponseStore {
    fn load_retry(&self, key: &SchedulerWorkKey) -> PortResult<Option<SchedulerRetryState>>;
    fn validate_lease(&self, work: &ScheduledWork) -> PortResult<()>;
    fn renew_lease(&self, request: &SchedulerLeaseRenewRequest) -> PortResult<ScheduledWork>;
    fn record_retry(&self, request: &SchedulerRetryRequest) -> PortResult<SchedulerRetryState>;
    fn acknowledge_health_event(
        &self,
        request: &SchedulerHealthAckRequest,
    ) -> PortResult<SchedulerRetryState>;
    fn release_lease(&self, request: &SchedulerLeaseReleaseRequest) -> PortResult<()>;
}

#[cfg(feature = "std")]
pub trait SchedulerHealthPort: Send + Sync {
    fn page_once(&self, request: &SchedulerHealthPageRequest) -> PortResult<()>;
}

#[cfg(feature = "std")]
pub trait ContainmentOverlayStore: Send + Sync {
    fn apply_contribution(&self, request: &OverlayApplyRequest) -> PortResult<OverlaySnapshot>;
    fn remove_contribution(&self, request: &OverlayRemoveRequest) -> PortResult<OverlaySnapshot>;
    fn load_effective(&self, target: &TenantScopedId) -> PortResult<Option<OverlaySnapshot>>;
}

#[cfg(feature = "std")]
pub trait BlastRadiusPort: Send + Sync {
    fn resolve(&self, request: &BlastRadiusRequest) -> PortResult<BlastRadiusResult>;
    fn acquire_fence(&self, request: &LineageFenceRequest) -> PortResult<LineageFence>;
    fn query_fence(&self, action: &TenantScopedId) -> PortResult<Option<LineageFence>>;
    fn release_fence(&self, release: &LineageFenceRelease) -> PortResult<()>;
}

#[cfg(feature = "std")]
pub trait LineageFenceStore: Send + Sync {
    fn acquire(&self, request: &LineageFenceRequest) -> PortResult<LineageFence>;
    fn query(&self, action: &TenantScopedId) -> PortResult<Option<LineageFence>>;
    fn release(&self, release: &LineageFenceRelease) -> PortResult<()>;
}

#[cfg(feature = "std")]
pub trait ApprovalVerifierPort: Send + Sync {
    fn verify_and_reserve(&self, request: &ApprovalRequest) -> PortResult<ApprovalReservation>;
    fn commit(&self, mutation: &ApprovalReservationMutation) -> PortResult<()>;
    fn cancel(&self, mutation: &ApprovalReservationMutation) -> PortResult<()>;
}

#[cfg(feature = "std")]
pub trait ApprovalReservationStore: Send + Sync {
    fn reserve(&self, request: &ApprovalReservationCreate) -> PortResult<CreateOutcome>;
    fn load_reservation(
        &self,
        action: &TenantScopedId,
    ) -> PortResult<Option<StoredApprovalReservation>>;
    fn commit_reservation(&self, mutation: &ApprovalReservationMutation) -> PortResult<()>;
    fn cancel_reservation(&self, mutation: &ApprovalReservationMutation) -> PortResult<()>;
}

#[cfg(feature = "std")]
pub trait EffectPort: Send + Sync {
    fn execute(&self, request: &EffectRequest) -> PortResult<EffectResult>;
    fn load_result(&self, query: &EffectResultQuery) -> PortResult<EffectExecutionStatus>;
}

#[cfg(feature = "std")]
pub trait SecurityReceiptSink: Send + Sync {
    fn sign_and_append(&self, request: &ReceiptAppendRequest) -> PortResult<OpaqueReceiptRef>;
}

#[cfg(feature = "std")]
pub trait SecurityAlertPort: Send + Sync {
    fn page(&self, alert: &SecurityAlert) -> PortResult<()>;
}
