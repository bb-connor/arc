//! Digest and identity domains cannot be substituted by assigning equal bytes.
//!
//! ```compile_fail
//! use chio_security_types::recovery::{NativeAdmissionDigest, ProcessRequestDigest};
//! let native = NativeAdmissionDigest::from_bytes([0; 32]);
//! let _: ProcessRequestDigest = native;
//! ```
//!
//! ```compile_fail
//! use chio_security_types::recovery::{ContinuationId, WorkflowId};
//! fn accept(_: WorkflowId) {}
//! let continuation = ContinuationId::new("continuation-a").unwrap_or_else(|e| panic!("{e}"));
//! accept(continuation);
//! ```
use super::{ContractError, SafeInteger};
use crate::ports::Digest32;
use alloc::string::{String, ToString};
use core::fmt;
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize,
};

/// Recovery identifiers are opaque ASCII values, never filesystem paths or URLs.
pub const MAX_RECOVERY_IDENTIFIER_BYTES: usize = 128;

macro_rules! identifier {
    ($($name:ident),+ $(,)?) => { $(
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);
        impl $name {
            pub fn new(value: &str) -> Result<Self, ContractError> {
                if value.is_empty() || value.len() > MAX_RECOVERY_IDENTIFIER_BYTES
                    || !value.as_bytes()[0].is_ascii_alphanumeric()
                    || !value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-')) {
                    return Err(ContractError::InvalidIdentifier);
                }
                Ok(Self(value.to_string()))
            }
            pub fn as_str(&self) -> &str { &self.0 }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(concat!(stringify!($name), "([redacted])")) }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct IdentifierVisitor;
                impl Visitor<'_> for IdentifierVisitor {
                    type Value = $name;
                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("a bounded opaque identifier") }
                    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                        $name::new(value).map_err(de::Error::custom)
                    }
                }
                d.deserialize_str(IdentifierVisitor)
            }
        }
    )+ };
}
identifier!(
    AuthorityDomainId,
    WorkflowId,
    StepId,
    ContinuationId,
    ProcessId,
    RecoveryTenantId,
    OperationId,
    EvidenceRef,
    AdmissionIntentRef,
    ApprovalIntentRef,
    ReleaseId,
    TemplateId,
    CreationKey,
    OfferId,
    ProviderAttemptId,
    PlanId,
    ProviderId,
    ProviderAccountId,
    ProviderResourceId,
    CommandId,
    ChallengeId,
    IssuerId,
    ReviewId,
    RequestId,
    ActorId,
    IsolationLineageId,
    ExplanationRef,
    ObservationId,
    SemanticPackageId,
    SemanticOperationId,
    SemanticFieldId,
    SemanticFactId,
    SemanticDestinationId,
    SemanticLeaseId,
    ArtifactId,
    ArtifactRevisionId,
    ArtifactObjectId,
    ArtifactHandleId,
    ArtifactRecipientId,
    CheckpointId,
    ModelContextId
);

// Retained effect routes use the existing RecordId codec, including its
// bounded Unicode profile. Distinct wrappers prevent provider/account
// substitution without narrowing an authenticated historical route.
macro_rules! effect_identity {
    ($($name:ident),+ $(,)?) => { $(
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(crate::ports::RecordId);
        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
                crate::ports::RecordId::new(value)
                    .map(Self)
                    .map_err(|_| ContractError::InvalidIdentifier)
            }
            pub fn as_str(&self) -> &str { self.0.as_str() }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    )+ };
}
effect_identity!(RecoveryEffectProviderId, RecoveryEffectAccountId);

// Keep the existing generated Digest32 representation (an exact 32-byte array).
macro_rules! digest {
    ($($name:ident),+ $(,)?) => { $(
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Digest32);
        impl $name {
            pub const fn from_bytes(bytes: [u8; 32]) -> Self { Self(Digest32::new(bytes)) }
            pub const fn as_bytes(&self) -> &[u8; 32] { self.0.as_bytes() }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(concat!(stringify!($name), "([redacted])")) }
        }
    )+ };
}
digest!(
    IntentDigest,
    CanonicalPayloadDigest,
    ProcessRequestDigest,
    ProcessCallBindingDigest,
    NativeAdmissionDigest,
    AuthorizationRequirementsDigest,
    ArtifactVersionId,
    PlanDigest,
    BasisDigest,
    OfferDigest,
    ExplanationDigest,
    DeploymentDigest,
    ContractDigest,
    ResourceDigest,
    ProfileDigest,
    RoleKeyDigest,
    CageMeasurementDigest,
    ConfinedCapabilityDigest,
    KnowledgeDigest,
    ReleaseAuthorizationDigest,
    ProvenanceDigest,
    ReturnContractDigest,
    PolicyDigest,
    SourceDigest,
    CoverageDigest,
    CapabilityBodyDigest,
    RequestNamespaceDigest,
    SemanticRequestDigest,
    OutputDispositionDigest,
    AuthorityScopeDigest,
    CommandDigest,
    ReviewDigest,
    SnapshotDigest,
    RemedyRegistryDigest,
    EvaluationDigest,
    ProjectionDigest,
    SemanticPackageDigest,
    SemanticRegistryDigest,
    SemanticActionDigest,
    SemanticEvidenceDigest
);

macro_rules! generation {
    ($($name:ident),+ $(,)?) => { $(
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(SafeInteger);
        impl $name {
            pub fn new(value: u64) -> Result<Self, ContractError> {
                if value == 0 { return Err(ContractError::InvalidState); }
                SafeInteger::new(value).map(Self)
            }
            pub const fn get(self) -> u64 { self.0.get() }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                Self::new(u64::deserialize(d)?).map_err(de::Error::custom)
            }
        }
    )+ };
}
generation!(PolicyGeneration, ServingEpoch);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effect_route_wrappers_preserve_the_retained_record_identity_codec(
    ) -> Result<(), alloc::boxed::Box<dyn core::error::Error>> {
        for value in [
            String::from("provider:ordinary"),
            String::from("legacy/provider"),
            "x".repeat(256),
            "é".repeat(128),
            "😀".repeat(64),
        ] {
            let old = crate::ports::RecordId::new(value.clone())?;
            let provider = RecoveryEffectProviderId::new(value.clone())?;
            let account = RecoveryEffectAccountId::new(value.clone())?;
            let old_wire = serde_json::to_vec(&old)?;
            assert_eq!(old_wire, serde_json::to_vec(&provider)?);
            assert_eq!(old_wire, serde_json::to_vec(&account)?);
            assert_eq!(
                serde_json::from_slice::<RecoveryEffectProviderId>(&old_wire)?.as_str(),
                value,
            );
            assert_eq!(
                serde_json::from_slice::<RecoveryEffectAccountId>(&old_wire)?.as_str(),
                value,
            );
        }
        for value in [
            String::new(),
            "x".repeat(257),
            "é".repeat(129),
            String::from(" a"),
            String::from("a\n"),
        ] {
            assert!(crate::ports::RecordId::new(value.clone()).is_err());
            assert!(RecoveryEffectProviderId::new(value.clone()).is_err());
            assert!(RecoveryEffectAccountId::new(value).is_err());
        }
        Ok(())
    }
}
