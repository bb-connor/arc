pub use crate::deception::{
    DecoyArtifactLookup, DecoyScan, SealedDecoyCasRequest, SealedDecoyPage, SealedDecoyRecord,
    SealedMarkerLookup, SealedPublicRefLookup, WatermarkObservation, WatermarkObservationResult,
    WatermarkSequenceReservation, WatermarkSequenceReservationResult,
};
use crate::{InformationLabel, ResponseEffectKind, ResponseTarget};
use alloc::boxed::Box;
#[cfg(feature = "std")]
use alloc::format;
use alloc::string::{String, ToString};
#[cfg(feature = "std")]
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

const MAX_ID_BYTES: usize = 256;
const MAX_CANONICAL_BODY_BYTES: usize = 1_048_576;
pub const RESPONSE_DISPATCH_AUTHORIZATION_SCHEMA_VERSION: u8 = 1;
pub const ATTESTED_FINDING_BATCH_SCHEMA_VERSION: u8 = 1;
pub const MAX_ATTESTED_FINDING_BATCH_SIZE: usize = 4_096;
pub const ATTESTED_FINDING_BATCH_ID_DOMAIN: &[u8] = b"chio.security.attested-finding-batch-id.v1\0";
pub const ATTESTED_FINDING_ACTION_ID_DOMAIN: &[u8] =
    b"chio.security.attested-finding-action-id.v1\0";
pub const ATTESTED_FINDING_RESERVATION_ID_DOMAIN: &[u8] =
    b"chio.security.attested-finding-reservation-id.v1\0";
pub const CONTAINMENT_TARGET_DOMAIN: &[u8] = b"chio.security.containment-target.v1\0";
pub const CONTAINMENT_OVERLAY_VERSION_DOMAIN: &[u8] = b"chio.response-effect-overlay-state.v1\0";
pub const CONTAINMENT_INSTALLED_CONTRIBUTION_DOMAIN: &[u8] =
    b"chio.response-effect-overlay-contribution.v1\0";
pub const SESSION_THROTTLE_VERSION_DOMAIN: &[u8] =
    b"chio.response-effect-session-throttle-state.v1\0";
pub const SESSION_THROTTLE_INSTALLED_CONTRIBUTION_DOMAIN: &[u8] =
    b"chio.response-effect-session-throttle-contribution.v1\0";
pub const SESSION_THROTTLE_WINDOW_DOMAIN: &[u8] =
    b"chio.response-effect-session-throttle-window.v1\0";
pub const RESPONSE_AFFECTED_SET_DOMAIN: &[u8] = b"chio.response-affected-set.v1\0";
pub const CAPABILITY_SET_SUSPENSION_VERSION_DOMAIN: &[u8] =
    b"chio.response-effect-capability-set-suspension-state.v1\0";
pub const CAPABILITY_SET_SUSPENSION_INSTALLED_CONTRIBUTION_DOMAIN: &[u8] =
    b"chio.response-effect-capability-set-suspension-contribution.v1\0";
pub const ISSUANCE_FREEZE_VERSION_DOMAIN: &[u8] =
    b"chio.response-effect-issuance-freeze-state.v1\0";
pub const ISSUANCE_FREEZE_INSTALLED_CONTRIBUTION_DOMAIN: &[u8] =
    b"chio.response-effect-issuance-freeze-contribution.v1\0";
pub const LINEAGE_FENCE_MAX_LEASE_MS: u64 = 60_000;
pub const LINEAGE_FENCE_RENEWAL_MARGIN_MS: u64 = 20_000;
pub const SESSION_THROTTLE_MAX_WINDOW_MS: u64 = 86_400_000;
pub const SESSION_THROTTLE_MAX_INVOCATIONS: u32 = 1_000_000;
pub const DECLASSIFICATION_EVIDENCE_SCHEMA_VERSION: u8 = 2;
pub const DECLASSIFICATION_EVIDENCE_INITIAL_RETRY_MS: u64 = 1_000;
pub const DECLASSIFICATION_EVIDENCE_MAX_RETRY_MS: u64 = 3_600_000;
pub const DECLASSIFICATION_EVIDENCE_RETENTION_MS: u64 = 7_776_000_000;
pub const DECLASSIFICATION_CONSUMPTION_TRANSITION_DOMAIN: &[u8] =
    b"chio.security.declassification.transition.consumption.v1\0";
pub const DECLASSIFICATION_RELEASED_TRANSITION_DOMAIN: &[u8] =
    b"chio.security.declassification.transition.released.v1\0";
pub const DECLASSIFICATION_DISPATCH_FAILED_TRANSITION_DOMAIN: &[u8] =
    b"chio.security.declassification.transition.dispatch-failed.v1\0";
pub const DECLASSIFICATION_OUTCOME_UNKNOWN_AFTER_DISPATCH_TRANSITION_DOMAIN: &[u8] =
    b"chio.security.declassification.transition.outcome-unknown-after-dispatch.v1\0";
pub const DECLASSIFICATION_RECEIPT_PERSISTENCE_FAILED_TRANSITION_DOMAIN: &[u8] =
    b"chio.security.declassification.transition.receipt-persistence-failed.v1\0";
pub const DECLASSIFICATION_RECOVERY_UNDELIVERED_TRANSITION_DOMAIN: &[u8] =
    b"chio.security.declassification.transition.recovery-undelivered-consumption.v1\0";
pub const DECLASSIFICATION_RECOVERY_OUTCOME_UNKNOWN_TRANSITION_DOMAIN: &[u8] =
    b"chio.security.declassification.transition.recovery-outcome-unknown.v1\0";
pub const DECLASSIFICATION_CONSUMPTION_EVENT_DOMAIN: &[u8] =
    b"chio.security.declassification.event.consumption.v1\0";
pub const DECLASSIFICATION_RELEASED_EVENT_DOMAIN: &[u8] =
    b"chio.security.declassification.event.released.v1\0";
pub const DECLASSIFICATION_DISPATCH_FAILED_EVENT_DOMAIN: &[u8] =
    b"chio.security.declassification.event.dispatch-failed.v1\0";
pub const DECLASSIFICATION_OUTCOME_UNKNOWN_AFTER_DISPATCH_EVENT_DOMAIN: &[u8] =
    b"chio.security.declassification.event.outcome-unknown-after-dispatch.v1\0";
pub const DECLASSIFICATION_RECEIPT_PERSISTENCE_FAILED_EVENT_DOMAIN: &[u8] =
    b"chio.security.declassification.event.receipt-persistence-failed.v1\0";
pub const DECLASSIFICATION_RECOVERY_UNDELIVERED_EVENT_DOMAIN: &[u8] =
    b"chio.security.declassification.event.recovery-undelivered-consumption.v1\0";
pub const DECLASSIFICATION_RECOVERY_OUTCOME_UNKNOWN_EVENT_DOMAIN: &[u8] =
    b"chio.security.declassification.event.recovery-outcome-unknown.v1\0";

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

fn validate_nonzero_id(value: &str) -> Result<(), IdError> {
    validate_id(value)?;
    if value.bytes().all(|byte| byte == b'0') {
        return Err(IdError::NonCanonical);
    }
    Ok(())
}

macro_rules! nonzero_id_type {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
                let value = value.into();
                validate_nonzero_id(&value)?;
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
                        formatter.write_str("a bounded canonical nonzero identifier")
                    }

                    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        validate_nonzero_id(value).map_err(E::custom)?;
                        Ok($name(String::from(value)))
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        validate_nonzero_id(value).map_err(E::custom)?;
                        Ok($name(String::from(value)))
                    }

                    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        validate_nonzero_id(&value).map_err(E::custom)?;
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
nonzero_id_type!(AdmissionArtifactRef);
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

    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
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
    pub fn map_ref<U>(&self, map: impl FnMut(&T) -> U) -> BoundedVec<U, MAX> {
        BoundedVec(self.0.iter().map(map).collect())
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
pub type UnverifiedEventBatch = BoundedVec<UnverifiedSecurityEvent, 4_096>;
pub type OverlayContributions = BoundedVec<OverlayContribution, 256>;
pub type SessionThrottleContributions = BoundedVec<SessionThrottleContribution, 256>;
pub type SessionThrottleWindowUsages = BoundedVec<SessionThrottleWindowUsage, 256>;
pub type CapabilitySetSuspensionContributions =
    BoundedVec<CapabilitySetSuspensionContribution, 256>;
pub type CapabilitySetSuspensionMatches = BoundedVec<CapabilitySetSuspensionMatch, 256>;
pub type IssuanceFreezeContributions = BoundedVec<IssuanceFreezeContribution, 256>;
pub type IssuanceFreezeMatches = BoundedVec<IssuanceFreezeMatch, 256>;
pub type EgressRestrictionContributions = BoundedVec<EgressRestrictionContribution, 256>;
pub type BlastRadiusSeeds = BoundedVec<RecordId, 256>;
pub type CausalLineageNodes = BoundedVec<CausalLineageNode, 4_096>;
pub type CausalLineageEdges = BoundedVec<CausalLineageEdge, 8_192>;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalSetError {
    Empty,
    TooManyItems,
    NotStrictlySorted,
}

impl fmt::Display for CanonicalSetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("canonical set is empty"),
            Self::TooManyItems => formatter.write_str("canonical set exceeds the item limit"),
            Self::NotStrictlySorted => {
                formatter.write_str("canonical set is not strictly sorted and unique")
            }
        }
    }
}

impl core::error::Error for CanonicalSetError {}

fn validate_canonical_set<T: Ord>(
    values: &[T],
    maximum: usize,
    allow_empty: bool,
) -> Result<(), CanonicalSetError> {
    if !allow_empty && values.is_empty() {
        return Err(CanonicalSetError::Empty);
    }
    if values.len() > maximum {
        return Err(CanonicalSetError::TooManyItems);
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(CanonicalSetError::NotStrictlySorted);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct EgressDestinationSet(BoundedVec<DestinationId, 64>);

impl EgressDestinationSet {
    pub fn new(values: Vec<DestinationId>) -> Result<Self, CanonicalSetError> {
        validate_canonical_set(&values, 64, false)?;
        BoundedVec::new(values)
            .map(Self)
            .map_err(|_| CanonicalSetError::TooManyItems)
    }

    #[must_use]
    pub fn as_slice(&self) -> &[DestinationId] {
        self.0.as_slice()
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

impl<'de> Deserialize<'de> for EgressDestinationSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = BoundedVec::<DestinationId, 64>::deserialize(deserializer)?.into_vec();
        Self::new(values).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct EgressDeniedDestinations(BoundedVec<DestinationId, 4_096>);

impl EgressDeniedDestinations {
    pub fn new(values: Vec<DestinationId>) -> Result<Self, CanonicalSetError> {
        validate_canonical_set(&values, 4_096, true)?;
        BoundedVec::new(values)
            .map(Self)
            .map_err(|_| CanonicalSetError::TooManyItems)
    }

    #[must_use]
    pub fn as_slice(&self) -> &[DestinationId] {
        self.0.as_slice()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'de> Deserialize<'de> for EgressDeniedDestinations {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = BoundedVec::<DestinationId, 4_096>::deserialize(deserializer)?.into_vec();
        Self::new(values).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct EgressRestrictionEffectIds(BoundedVec<EffectId, 256>);

impl EgressRestrictionEffectIds {
    pub fn new(values: Vec<EffectId>) -> Result<Self, CanonicalSetError> {
        validate_canonical_set(&values, 256, true)?;
        BoundedVec::new(values)
            .map(Self)
            .map_err(|_| CanonicalSetError::TooManyItems)
    }

    #[must_use]
    pub fn as_slice(&self) -> &[EffectId] {
        self.0.as_slice()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'de> Deserialize<'de> for EgressRestrictionEffectIds {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = BoundedVec::<EffectId, 256>::deserialize(deserializer)?.into_vec();
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
    pub grant_expires_at_unix_ms: u64,
}

pub fn declassification_retain_until_unix_ms(grant_expires_at_unix_ms: u64) -> PortResult<u64> {
    grant_expires_at_unix_ms
        .checked_add(DECLASSIFICATION_EVIDENCE_RETENTION_MS)
        .ok_or_else(PortError::invalid_data)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclassificationUseState {
    ConsumedPendingDispatch,
    Released,
    DispatchFailed,
    OutcomeUnknown,
}

/// Closed, bounded input to declassification transition and event identity.
///
/// Each identity preimage starts with its fixed variant domain and then the
/// listed fields in declaration order. Every field is encoded as an unsigned
/// 64-bit big-endian byte length followed by the exact field bytes. Digests
/// contribute their 32 raw bytes. Callers cannot supply a domain.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum DeclassificationTransitionBinding {
    Consumption {
        tenant_id: TenantId,
        grant_id: GrantId,
        request_hash: Digest32,
        request_id: RequestId,
    },
    Released {
        tenant_id: TenantId,
        grant_id: GrantId,
        request_hash: Digest32,
        request_id: RequestId,
        dispatch_commitment_id: RecordId,
    },
    DispatchFailed {
        tenant_id: TenantId,
        grant_id: GrantId,
        request_hash: Digest32,
        request_id: RequestId,
        dispatch_commitment_id: RecordId,
    },
    OutcomeUnknownAfterDispatch {
        tenant_id: TenantId,
        grant_id: GrantId,
        request_hash: Digest32,
        request_id: RequestId,
        dispatch_commitment_id: RecordId,
    },
    ReceiptPersistenceFailed {
        tenant_id: TenantId,
        grant_id: GrantId,
        request_hash: Digest32,
        request_id: RequestId,
        dispatch_commitment_id: RecordId,
    },
    RecoveryUndeliveredConsumption {
        tenant_id: TenantId,
        grant_id: GrantId,
        request_hash: Digest32,
        predecessor_evidence_id: OpaqueReceiptRef,
        predecessor_transition_id: RecordId,
    },
    RecoveryOutcomeUnknown {
        tenant_id: TenantId,
        grant_id: GrantId,
        request_hash: Digest32,
        predecessor_evidence_id: OpaqueReceiptRef,
        predecessor_transition_id: RecordId,
    },
}

impl DeclassificationTransitionBinding {
    #[must_use]
    pub const fn terminal_state(&self) -> Option<DeclassificationUseState> {
        match self {
            Self::Consumption { .. } => None,
            Self::Released { .. } => Some(DeclassificationUseState::Released),
            Self::DispatchFailed { .. }
            | Self::ReceiptPersistenceFailed { .. }
            | Self::RecoveryUndeliveredConsumption { .. } => {
                Some(DeclassificationUseState::DispatchFailed)
            }
            Self::OutcomeUnknownAfterDispatch { .. }
            | Self::RecoveryOutcomeUnknown { .. } => {
                Some(DeclassificationUseState::OutcomeUnknown)
            }
        }
    }

    #[must_use]
    pub const fn is_live_dispatch_binding(&self) -> bool {
        matches!(
            self,
            Self::Released { .. }
                | Self::DispatchFailed { .. }
                | Self::OutcomeUnknownAfterDispatch { .. }
                | Self::ReceiptPersistenceFailed { .. }
        )
    }

    #[must_use]
    pub const fn is_consumption(&self) -> bool {
        matches!(self, Self::Consumption { .. })
    }

    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        match self {
            Self::Consumption { tenant_id, .. }
            | Self::Released { tenant_id, .. }
            | Self::DispatchFailed { tenant_id, .. }
            | Self::OutcomeUnknownAfterDispatch { tenant_id, .. }
            | Self::ReceiptPersistenceFailed { tenant_id, .. }
            | Self::RecoveryUndeliveredConsumption { tenant_id, .. }
            | Self::RecoveryOutcomeUnknown { tenant_id, .. } => tenant_id,
        }
    }

    #[must_use]
    pub const fn grant_id(&self) -> &GrantId {
        match self {
            Self::Consumption { grant_id, .. }
            | Self::Released { grant_id, .. }
            | Self::DispatchFailed { grant_id, .. }
            | Self::OutcomeUnknownAfterDispatch { grant_id, .. }
            | Self::ReceiptPersistenceFailed { grant_id, .. }
            | Self::RecoveryUndeliveredConsumption { grant_id, .. }
            | Self::RecoveryOutcomeUnknown { grant_id, .. } => grant_id,
        }
    }

    #[must_use]
    pub const fn request_hash(&self) -> Digest32 {
        match self {
            Self::Consumption { request_hash, .. }
            | Self::Released { request_hash, .. }
            | Self::DispatchFailed { request_hash, .. }
            | Self::OutcomeUnknownAfterDispatch { request_hash, .. }
            | Self::ReceiptPersistenceFailed { request_hash, .. }
            | Self::RecoveryUndeliveredConsumption { request_hash, .. }
            | Self::RecoveryOutcomeUnknown { request_hash, .. } => *request_hash,
        }
    }

    #[must_use]
    pub const fn recovery_predecessor(&self) -> Option<(&OpaqueReceiptRef, &RecordId)> {
        match self {
            Self::RecoveryUndeliveredConsumption {
                predecessor_evidence_id,
                predecessor_transition_id,
                ..
            }
            | Self::RecoveryOutcomeUnknown {
                predecessor_evidence_id,
                predecessor_transition_id,
                ..
            } => Some((predecessor_evidence_id, predecessor_transition_id)),
            Self::Consumption { .. }
            | Self::Released { .. }
            | Self::DispatchFailed { .. }
            | Self::OutcomeUnknownAfterDispatch { .. }
            | Self::ReceiptPersistenceFailed { .. } => None,
        }
    }

    #[cfg(feature = "std")]
    const fn transition_domain(&self) -> &'static [u8] {
        match self {
            Self::Consumption { .. } => DECLASSIFICATION_CONSUMPTION_TRANSITION_DOMAIN,
            Self::Released { .. } => DECLASSIFICATION_RELEASED_TRANSITION_DOMAIN,
            Self::DispatchFailed { .. } => DECLASSIFICATION_DISPATCH_FAILED_TRANSITION_DOMAIN,
            Self::OutcomeUnknownAfterDispatch { .. } => {
                DECLASSIFICATION_OUTCOME_UNKNOWN_AFTER_DISPATCH_TRANSITION_DOMAIN
            }
            Self::ReceiptPersistenceFailed { .. } => {
                DECLASSIFICATION_RECEIPT_PERSISTENCE_FAILED_TRANSITION_DOMAIN
            }
            Self::RecoveryUndeliveredConsumption { .. } => {
                DECLASSIFICATION_RECOVERY_UNDELIVERED_TRANSITION_DOMAIN
            }
            Self::RecoveryOutcomeUnknown { .. } => {
                DECLASSIFICATION_RECOVERY_OUTCOME_UNKNOWN_TRANSITION_DOMAIN
            }
        }
    }

    #[cfg(feature = "std")]
    const fn event_domain(&self) -> &'static [u8] {
        match self {
            Self::Consumption { .. } => DECLASSIFICATION_CONSUMPTION_EVENT_DOMAIN,
            Self::Released { .. } => DECLASSIFICATION_RELEASED_EVENT_DOMAIN,
            Self::DispatchFailed { .. } => DECLASSIFICATION_DISPATCH_FAILED_EVENT_DOMAIN,
            Self::OutcomeUnknownAfterDispatch { .. } => {
                DECLASSIFICATION_OUTCOME_UNKNOWN_AFTER_DISPATCH_EVENT_DOMAIN
            }
            Self::ReceiptPersistenceFailed { .. } => {
                DECLASSIFICATION_RECEIPT_PERSISTENCE_FAILED_EVENT_DOMAIN
            }
            Self::RecoveryUndeliveredConsumption { .. } => {
                DECLASSIFICATION_RECOVERY_UNDELIVERED_EVENT_DOMAIN
            }
            Self::RecoveryOutcomeUnknown { .. } => {
                DECLASSIFICATION_RECOVERY_OUTCOME_UNKNOWN_EVENT_DOMAIN
            }
        }
    }

    #[cfg(feature = "std")]
    fn fields(&self) -> Vec<&[u8]> {
        match self {
            Self::Consumption {
                tenant_id,
                grant_id,
                request_hash,
                request_id,
            } => vec![
                tenant_id.as_str().as_bytes(),
                grant_id.as_str().as_bytes(),
                request_hash.as_bytes(),
                request_id.as_str().as_bytes(),
            ],
            Self::Released {
                tenant_id,
                grant_id,
                request_hash,
                request_id,
                dispatch_commitment_id,
            }
            | Self::DispatchFailed {
                tenant_id,
                grant_id,
                request_hash,
                request_id,
                dispatch_commitment_id,
            }
            | Self::OutcomeUnknownAfterDispatch {
                tenant_id,
                grant_id,
                request_hash,
                request_id,
                dispatch_commitment_id,
            }
            | Self::ReceiptPersistenceFailed {
                tenant_id,
                grant_id,
                request_hash,
                request_id,
                dispatch_commitment_id,
            } => vec![
                tenant_id.as_str().as_bytes(),
                grant_id.as_str().as_bytes(),
                request_hash.as_bytes(),
                request_id.as_str().as_bytes(),
                dispatch_commitment_id.as_str().as_bytes(),
            ],
            Self::RecoveryUndeliveredConsumption {
                tenant_id,
                grant_id,
                request_hash,
                predecessor_evidence_id,
                predecessor_transition_id,
            }
            | Self::RecoveryOutcomeUnknown {
                tenant_id,
                grant_id,
                request_hash,
                predecessor_evidence_id,
                predecessor_transition_id,
            } => vec![
                tenant_id.as_str().as_bytes(),
                grant_id.as_str().as_bytes(),
                request_hash.as_bytes(),
                predecessor_evidence_id.as_str().as_bytes(),
                predecessor_transition_id.as_str().as_bytes(),
            ],
        }
    }
}

#[cfg(feature = "std")]
fn declassification_binding_digest(
    domain: &[u8],
    binding: &DeclassificationTransitionBinding,
) -> PortResult<[u8; 32]> {
    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in binding.fields() {
        let length = u64::try_from(field.len()).map_err(|_| PortError::invalid_data())?;
        hasher.update(length.to_be_bytes());
        hasher.update(field);
    }
    Ok(hasher.finalize().into())
}

#[cfg(feature = "std")]
fn declassification_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(feature = "std")]
#[must_use = "derived transition IDs must be persisted or verified"]
pub fn derive_declassification_transition_id(
    binding: &DeclassificationTransitionBinding,
) -> PortResult<RecordId> {
    let digest = declassification_binding_digest(binding.transition_domain(), binding)?;
    RecordId::new(format!(
        "declassification-transition:{}",
        declassification_hex(&digest)
    ))
    .map_err(PortError::from)
}

#[cfg(feature = "std")]
#[must_use = "derived event IDs must be persisted or verified"]
pub fn derive_declassification_event_id(
    binding: &DeclassificationTransitionBinding,
) -> PortResult<EventId> {
    let digest = declassification_binding_digest(binding.event_domain(), binding)?;
    EventId::new(format!(
        "declassification-event:{}",
        declassification_hex(&digest)
    ))
    .map_err(PortError::from)
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

pub const MAX_DECLASSIFICATION_EVIDENCE_BATCH: u32 = 1_024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclassificationEvidencePhase {
    Consumption,
    Outcome,
}

impl DeclassificationEvidencePhase {
    #[must_use]
    pub const fn ordinal(self) -> u8 {
        match self {
            Self::Consumption => 0,
            Self::Outcome => 1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationConsumptionEvidenceCommit {
    pub consumption: DeclassificationConsumeRequest,
    pub transition_binding: DeclassificationTransitionBinding,
    pub receipt: ReceiptAppendRequest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationOutcomeEvidenceCommit {
    pub outcome: DeclassificationOutcomeRequest,
    pub transition_binding: DeclassificationTransitionBinding,
    pub predecessor_evidence_id: OpaqueReceiptRef,
    pub receipt: ReceiptAppendRequest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationUseQuery {
    pub tenant_id: TenantId,
    pub grant_id: GrantId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationUseRecord {
    pub tenant_id: TenantId,
    pub grant_id: GrantId,
    pub request_hash: Digest32,
    pub state: DeclassificationUseState,
    pub consumed_at_unix_ms: u64,
    pub grant_expires_at_unix_ms: u64,
    pub retain_until_unix_ms: u64,
    pub consumption_binding: DeclassificationTransitionBinding,
    pub outcome_binding: Option<DeclassificationTransitionBinding>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationEvidenceQuery {
    pub tenant_id: TenantId,
    pub grant_id: GrantId,
    pub phase: DeclassificationEvidencePhase,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationEvidencePendingQuery {
    pub tenant_id: TenantId,
    pub grant_id: GrantId,
    pub now_unix_ms: u64,
    pub max_records: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationEvidenceRecord {
    pub tenant_id: TenantId,
    pub grant_id: GrantId,
    pub phase: DeclassificationEvidencePhase,
    pub request_hash: Digest32,
    pub state: DeclassificationUseState,
    pub transition_binding: DeclassificationTransitionBinding,
    pub predecessor_evidence_id: Option<OpaqueReceiptRef>,
    pub receipt: ReceiptAppendRequest,
    pub acknowledged: bool,
    pub durable_sink_record_hash: Option<Digest32>,
    pub attempts: u32,
    pub next_attempt_at_unix_ms: u64,
    pub last_error_code: Option<ErrorCode>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationEvidenceAckRequest {
    pub tenant_id: TenantId,
    pub grant_id: GrantId,
    pub phase: DeclassificationEvidencePhase,
    pub evidence_id: OpaqueReceiptRef,
    pub body_hash: Digest32,
    pub transition_id: RecordId,
    pub durable_sink_record_hash: Digest32,
    pub verified_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationEvidenceRetryRequest {
    pub tenant_id: TenantId,
    pub grant_id: GrantId,
    pub phase: DeclassificationEvidencePhase,
    pub evidence_id: OpaqueReceiptRef,
    pub body_hash: Digest32,
    pub transition_id: RecordId,
    pub failed_at_unix_ms: u64,
    pub error_code: ErrorCode,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationCompactionQuery {
    pub readiness_cursor: RecordId,
    pub now_unix_ms: u64,
    pub after_tenant_id: Option<TenantId>,
    pub after_grant_id: Option<GrantId>,
    pub max_records: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationCompactionCandidate {
    pub readiness_cursor: RecordId,
    pub use_record: DeclassificationUseRecord,
    pub consumption: DeclassificationEvidenceRecord,
    pub outcome: DeclassificationEvidenceRecord,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationCompactionRequest {
    pub readiness_cursor: RecordId,
    pub tenant_id: TenantId,
    pub grant_id: GrantId,
    pub request_hash: Digest32,
    pub terminal_state: DeclassificationUseState,
    pub consumption_evidence_id: OpaqueReceiptRef,
    pub consumption_body_hash: Digest32,
    pub consumption_transition_id: RecordId,
    pub consumption_occurred_at_unix_ms: u64,
    pub consumption_sink_record_hash: Digest32,
    pub outcome_evidence_id: OpaqueReceiptRef,
    pub outcome_body_hash: Digest32,
    pub outcome_transition_id: RecordId,
    pub outcome_occurred_at_unix_ms: u64,
    pub outcome_sink_record_hash: Digest32,
    pub policy_hash: Digest32,
    pub compacted_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationEvidenceTombstone {
    pub tenant_id: TenantId,
    pub grant_id: GrantId,
    pub request_hash: Digest32,
    pub terminal_state: DeclassificationUseState,
    pub consumption_evidence_id: OpaqueReceiptRef,
    pub consumption_body_hash: Digest32,
    pub consumption_transition_id: RecordId,
    pub consumption_occurred_at_unix_ms: u64,
    pub consumption_sink_record_hash: Digest32,
    pub outcome_evidence_id: OpaqueReceiptRef,
    pub outcome_body_hash: Digest32,
    pub outcome_transition_id: RecordId,
    pub outcome_occurred_at_unix_ms: u64,
    pub outcome_sink_record_hash: Digest32,
    pub policy_hash: Digest32,
    pub compacted_at_unix_ms: u64,
}

#[cfg(feature = "std")]
pub fn declassification_retry_deadline_unix_ms(
    failed_at_unix_ms: u64,
    attempts_after_failure: u32,
) -> PortResult<u64> {
    if attempts_after_failure == 0 {
        return Err(PortError::invalid_data());
    }
    let exponent = attempts_after_failure.saturating_sub(1).min(63);
    let multiplier = 1_u64
        .checked_shl(exponent)
        .ok_or_else(PortError::integrity_failure)?;
    let backoff = match DECLASSIFICATION_EVIDENCE_INITIAL_RETRY_MS.checked_mul(multiplier) {
        Some(value) => value.min(DECLASSIFICATION_EVIDENCE_MAX_RETRY_MS),
        None => DECLASSIFICATION_EVIDENCE_MAX_RETRY_MS,
    };
    failed_at_unix_ms
        .checked_add(backoff)
        .ok_or_else(PortError::integrity_failure)
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

/// One crash-atomic correlation ingress mutation.
///
/// The verified event, its per-rule partition ownership, and the optional
/// tenant-rule capacity reservation either all commit or all remain absent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationEventAdmissionRequest {
    pub event: VerifiedSecurityEvent,
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

/// One authoritative finding's durable identity in the response-planning
/// queue. Policy-specific response fields are deliberately absent. The
/// planning policy consumes this identity before it builds an executable
/// response plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttestedFindingBatchBinding {
    pub tenant_id: TenantId,
    pub evidence_id: OpaqueReceiptRef,
    pub finding_id: RecordId,
    pub finding_hash: Digest32,
    pub action_id: ActionId,
    pub reservation_id: RecordId,
}

pub type AttestedFindingBatchBindings =
    BoundedVec<AttestedFindingBatchBinding, MAX_ATTESTED_FINDING_BATCH_SIZE>;

/// Canonical crash-recovery body for one ordered planning publication.
///
/// `batch_id`, every `action_id`, and every `reservation_id` are derived from the
/// exact ordered authoritative finding identities. This assigns durable work
/// identities without inventing response effects, approval policy, TTL, or
/// operator authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttestedFindingBatchBody {
    pub schema_version: u8,
    pub batch_id: RecordId,
    pub tenant_id: TenantId,
    pub bindings: AttestedFindingBatchBindings,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttestedFindingBatchPublication {
    pub body: AttestedFindingBatchBody,
    pub canonical_body: CanonicalBody,
    pub body_hash: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttestedFindingBatchKey {
    pub tenant_id: TenantId,
    pub batch_id: RecordId,
}

#[cfg(feature = "std")]
fn attested_finding_derived_id(
    domain: &[u8],
    prefix: &str,
    components: &[&[u8]],
) -> PortResult<String> {
    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(domain);
    for component in components {
        let length = u64::try_from(component.len()).map_err(|_| PortError::invalid_data())?;
        hasher.update(length.to_be_bytes());
        hasher.update(component);
    }
    let digest = hasher.finalize();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut suffix = String::with_capacity(digest.len().saturating_mul(2));
    for byte in digest {
        suffix.push(char::from(HEX[usize::from(byte >> 4)]));
        suffix.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(format!("{prefix}-{suffix}"))
}

/// Derive the idempotency key for one exact ordered finding batch.
#[cfg(feature = "std")]
pub fn derive_attested_finding_batch_id(
    ordered_evidence_ids: &[OpaqueReceiptRef],
) -> PortResult<RecordId> {
    if ordered_evidence_ids.is_empty()
        || ordered_evidence_ids.len() > MAX_ATTESTED_FINDING_BATCH_SIZE
    {
        return Err(PortError::invalid_data());
    }
    let mut unique = alloc::collections::BTreeSet::new();
    if ordered_evidence_ids
        .iter()
        .any(|evidence_id| !unique.insert(evidence_id))
    {
        return Err(PortError::invalid_data());
    }
    let components = ordered_evidence_ids
        .iter()
        .map(|evidence_id| evidence_id.as_str().as_bytes())
        .collect::<Vec<_>>();
    RecordId::new(attested_finding_derived_id(
        ATTESTED_FINDING_BATCH_ID_DOMAIN,
        "finding-batch",
        &components,
    )?)
    .map_err(PortError::from)
}

/// Derive the future response plan identity for one authoritative finding.
#[cfg(feature = "std")]
pub fn derive_attested_finding_action_id(
    batch_id: &RecordId,
    ordinal: usize,
    tenant_id: &TenantId,
    evidence_id: &OpaqueReceiptRef,
    finding_id: &RecordId,
    finding_hash: &Digest32,
) -> PortResult<ActionId> {
    let ordinal = u64::try_from(ordinal).map_err(|_| PortError::invalid_data())?;
    ActionId::new(attested_finding_derived_id(
        ATTESTED_FINDING_ACTION_ID_DOMAIN,
        "response-action",
        &[
            batch_id.as_str().as_bytes(),
            &ordinal.to_be_bytes(),
            tenant_id.as_str().as_bytes(),
            evidence_id.as_str().as_bytes(),
            finding_id.as_str().as_bytes(),
            finding_hash.as_bytes(),
        ],
    )?)
    .map_err(PortError::from)
}

/// Derive the planning reservation identity for one future response plan.
#[cfg(feature = "std")]
pub fn derive_attested_finding_reservation_id(
    batch_id: &RecordId,
    action_id: &ActionId,
    evidence_id: &OpaqueReceiptRef,
) -> PortResult<RecordId> {
    RecordId::new(attested_finding_derived_id(
        ATTESTED_FINDING_RESERVATION_ID_DOMAIN,
        "response-reservation",
        &[
            batch_id.as_str().as_bytes(),
            action_id.as_str().as_bytes(),
            evidence_id.as_str().as_bytes(),
        ],
    )?)
    .map_err(PortError::from)
}
