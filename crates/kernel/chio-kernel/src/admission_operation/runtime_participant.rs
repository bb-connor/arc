//! Operation-bound runtime replay claims. These values describe exact intent
//! and historical references; none substitutes for a live store-owner lease.

use super::{
    AdmissionDigest, AdmissionIdentifier, AdmissionOperationId, AdmissionOperationStoreError,
    RuntimeReplayParticipantKind,
};
use serde::{Deserialize, Serialize};

/// The runtime hook currently consumes at most one resource of each kind.
pub const MAX_RUNTIME_PARTICIPANTS: usize = 3;

/// Hard bound on complete, retained claim history for one operation.
pub const MAX_RUNTIME_PARTICIPANT_EPISODES: usize = 128;

/// Bounded freshness data returned by the configured runtime verifier. This is
/// not a dispatch permit, an authenticated claim or a persisted replay token.
/// The kernel binds it to actual live custody; the capture transaction must
/// check it again immediately before commit without calling an external hook.
#[derive(Debug, Eq, PartialEq)]
pub struct RuntimeDispatchValidity {
    verified_at_unix_ms: u64,
    valid_until_unix_ms: u64,
}

impl RuntimeDispatchValidity {
    pub fn new(
        verified_at_unix_ms: u64,
        valid_until_unix_ms: u64,
    ) -> Result<Self, AdmissionOperationStoreError> {
        if verified_at_unix_ms >= valid_until_unix_ms || valid_until_unix_ms > (1_u64 << 53) - 1 {
            return Err(AdmissionOperationStoreError::Invariant(
                "runtime dispatch validity is empty or outside canonical time".into(),
            ));
        }
        Ok(Self {
            verified_at_unix_ms,
            valid_until_unix_ms,
        })
    }

    pub fn validate_at(&self, now_unix_ms: u64) -> Result<(), AdmissionOperationStoreError> {
        if now_unix_ms < self.verified_at_unix_ms || now_unix_ms >= self.valid_until_unix_ms {
            return Err(AdmissionOperationStoreError::Invariant(
                "runtime dispatch evidence is not valid at capture".into(),
            ));
        }
        Ok(())
    }

    pub fn valid_until_unix_ms(&self) -> u64 {
        self.valid_until_unix_ms
    }
}

/// Trusted configuration data identifying one imported source generation. This
/// value is not activation evidence, an operation lease or a claim authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeParticipantAuthorityBindingV1 {
    runtime_authority_id: AdmissionIdentifier,
    expectation_id: AdmissionIdentifier,
}

impl RuntimeParticipantAuthorityBindingV1 {
    pub fn new(
        runtime_authority_id: AdmissionIdentifier,
        expectation_id: AdmissionIdentifier,
    ) -> Self {
        Self {
            runtime_authority_id,
            expectation_id,
        }
    }

    pub fn runtime_authority_id(&self) -> &AdmissionIdentifier {
        &self.runtime_authority_id
    }

    pub fn expectation_id(&self) -> &AdmissionIdentifier {
        &self.expectation_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeParticipantPhase {
    NoncePreflight,
    Dispatch,
}

/// Historical disposition, never an executable permit or release authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeParticipantDisposition {
    ReservedBeforeDispatch,
    ReleasedBeforeDispatch,
    RetainedAfterDispatchCommit,
}

/// Readback data for interruption recovery. The actual current operation lease
/// is still required for release; a retained plan must not be executed again.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeParticipantClaimHistoryV1 {
    pub reference: RuntimeParticipantClaimReferenceV1,
    pub intent: RuntimeParticipantClaimIntentV1,
    pub disposition: RuntimeParticipantDisposition,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeParticipantResourceV1 {
    kind: RuntimeReplayParticipantKind,
    resource_id: AdmissionIdentifier,
    artifact_digest: AdmissionDigest,
}

impl RuntimeParticipantResourceV1 {
    pub fn new(
        kind: RuntimeReplayParticipantKind,
        resource_id: AdmissionIdentifier,
        artifact_digest: AdmissionDigest,
    ) -> Self {
        Self {
            kind,
            resource_id,
            artifact_digest,
        }
    }

    pub fn kind(&self) -> RuntimeReplayParticipantKind {
        self.kind
    }

    pub fn resource_id(&self) -> &AdmissionIdentifier {
        &self.resource_id
    }

    pub fn artifact_digest(&self) -> &AdmissionDigest {
        &self.artifact_digest
    }
}

/// Intent from the configured verifier after complete runtime preparation.
/// The store separately checks original request provenance, the selected grant,
/// migration generation, resource conflicts and current coordinator authority.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    deny_unknown_fields,
    try_from = "RuntimeParticipantClaimIntentInput"
)]
pub struct RuntimeParticipantClaimIntentV1 {
    episode_id: AdmissionIdentifier,
    runtime_authority_id: AdmissionIdentifier,
    expectation_id: AdmissionIdentifier,
    request_binding_hash: AdmissionDigest,
    grant_index: u32,
    phase: RuntimeParticipantPhase,
    plan_digest: AdmissionDigest,
    resources: Vec<RuntimeParticipantResourceV1>,
}

impl std::fmt::Debug for RuntimeParticipantClaimIntentV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeParticipantClaimIntentV1")
            .field("episode_id", &self.episode_id)
            .field("runtime_authority_id", &self.runtime_authority_id)
            .field("phase", &self.phase)
            .field("grant_index", &self.grant_index)
            .field("plan_digest", &self.plan_digest)
            .field("resource_count", &self.resources.len())
            .finish_non_exhaustive()
    }
}

/// Construction input is data, not a caller-asserted ownership token.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeParticipantClaimIntentInput {
    pub episode_id: AdmissionIdentifier,
    pub runtime_authority_id: AdmissionIdentifier,
    pub expectation_id: AdmissionIdentifier,
    pub request_binding_hash: AdmissionDigest,
    pub grant_index: u32,
    pub phase: RuntimeParticipantPhase,
    pub plan_digest: AdmissionDigest,
    pub resources: Vec<RuntimeParticipantResourceV1>,
}

impl TryFrom<RuntimeParticipantClaimIntentInput> for RuntimeParticipantClaimIntentV1 {
    type Error = AdmissionOperationStoreError;

    fn try_from(input: RuntimeParticipantClaimIntentInput) -> Result<Self, Self::Error> {
        Self::new(input)
    }
}

impl RuntimeParticipantClaimIntentV1 {
    pub fn new(
        input: RuntimeParticipantClaimIntentInput,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let intent = Self {
            episode_id: input.episode_id,
            runtime_authority_id: input.runtime_authority_id,
            expectation_id: input.expectation_id,
            request_binding_hash: input.request_binding_hash,
            grant_index: input.grant_index,
            phase: input.phase,
            plan_digest: input.plan_digest,
            resources: input.resources,
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn validate(&self) -> Result<(), AdmissionOperationStoreError> {
        if self.resources.len() > MAX_RUNTIME_PARTICIPANTS
            || self
                .resources
                .windows(2)
                .any(|pair| pair[0].kind >= pair[1].kind)
        {
            return Err(AdmissionOperationStoreError::Invariant(
                "runtime participants must be an ordered set with at most one resource per kind"
                    .into(),
            ));
        }
        Ok(())
    }

    pub fn episode_id(&self) -> &AdmissionIdentifier {
        &self.episode_id
    }

    pub fn runtime_authority_id(&self) -> &AdmissionIdentifier {
        &self.runtime_authority_id
    }

    pub fn expectation_id(&self) -> &AdmissionIdentifier {
        &self.expectation_id
    }

    pub fn request_binding_hash(&self) -> &AdmissionDigest {
        &self.request_binding_hash
    }

    pub fn grant_index(&self) -> u32 {
        self.grant_index
    }

    pub fn phase(&self) -> RuntimeParticipantPhase {
        self.phase
    }

    pub fn plan_digest(&self) -> &AdmissionDigest {
        &self.plan_digest
    }

    pub fn resources(&self) -> &[RuntimeParticipantResourceV1] {
        &self.resources
    }
}

/// An exact historical lookup key. Possession does not permit release: the
/// store must verify its physical record and the current recovery lease.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeParticipantClaimReferenceV1 {
    operation_id: AdmissionOperationId,
    episode_id: AdmissionIdentifier,
    claim_digest: AdmissionDigest,
}

impl RuntimeParticipantClaimReferenceV1 {
    pub fn new(
        operation_id: AdmissionOperationId,
        episode_id: AdmissionIdentifier,
        claim_digest: AdmissionDigest,
    ) -> Self {
        Self {
            operation_id,
            episode_id,
            claim_digest,
        }
    }

    pub fn operation_id(&self) -> &AdmissionOperationId {
        &self.operation_id
    }

    pub fn episode_id(&self) -> &AdmissionIdentifier {
        &self.episode_id
    }

    pub fn claim_digest(&self) -> &AdmissionDigest {
        &self.claim_digest
    }
}

#[cfg(test)]
mod validity_tests {
    use super::*;

    #[test]
    fn runtime_dispatch_validity_is_bounded_and_exclusive(
    ) -> Result<(), AdmissionOperationStoreError> {
        for (start, end) in [(1, 1), (2, 1), (1, 1_u64 << 53), (0, u64::MAX)] {
            assert!(RuntimeDispatchValidity::new(start, end).is_err());
        }
        let validity = RuntimeDispatchValidity::new(100, 200)?;
        assert!(validity.validate_at(99).is_err());
        assert!(validity.validate_at(100).is_ok());
        assert!(validity.validate_at(199).is_ok());
        assert!(validity.validate_at(200).is_err());
        assert!(validity.validate_at(u64::MAX).is_err());
        Ok(())
    }
}
