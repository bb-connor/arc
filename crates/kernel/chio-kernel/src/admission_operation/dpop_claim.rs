//! Bounded DPoP replay custody data. Decoding history is not signature
//! verification, configured authority, an operation lease or dispatch permission.

use super::AdmissionOperationStoreError as Error;
use super::{AdmissionDigest, AdmissionIdentifier, AdmissionOperationId};
use crate::dpop::authority::{DpopReplayAuthorityV1, VerifiedDpopReplayProof};
use serde::{Deserialize, Serialize};

pub const MAX_DPOP_CLAIM_EPISODES: usize = 128;
const MAX_UNIX_SECS: u64 = 9_007_199_254_740;

/// Non-executable proof commitment. The reusable proof signature is not retained.
/// Nonce and capability identity are exact UTF-8, never trimmed or normalized.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    try_from = "CredentialInput",
    deny_unknown_fields
)]
pub struct DpopReplayCredentialV1 {
    authority: DpopReplayAuthorityV1,
    capability_id: String,
    nonce: String,
    invocation_digest: AdmissionDigest,
    proof_digest: AdmissionDigest,
    issued_at_unix_secs: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CredentialInput {
    authority: DpopReplayAuthorityV1,
    capability_id: String,
    nonce: String,
    invocation_digest: AdmissionDigest,
    proof_digest: AdmissionDigest,
    issued_at_unix_secs: u64,
}
impl TryFrom<CredentialInput> for DpopReplayCredentialV1 {
    type Error = Error;
    fn try_from(input: CredentialInput) -> Result<Self, Error> {
        let value = Self {
            authority: input.authority,
            capability_id: input.capability_id,
            nonce: input.nonce,
            invocation_digest: input.invocation_digest,
            proof_digest: input.proof_digest,
            issued_at_unix_secs: input.issued_at_unix_secs,
        };
        value.validate()?;
        Ok(value)
    }
}
impl DpopReplayCredentialV1 {
    /// Consume cryptographic verification output. This conversion does not
    /// establish activation or the configured kernel's capability/policy checks.
    pub fn from_verified(proof: VerifiedDpopReplayProof) -> Self {
        Self {
            authority: proof.authority().clone(),
            capability_id: proof.capability_id().into(),
            nonce: proof.nonce().into(),
            invocation_digest: proof.invocation_digest().clone(),
            proof_digest: proof.proof_digest().clone(),
            issued_at_unix_secs: proof.issued_at_unix_secs(),
        }
    }
    pub fn validate(&self) -> Result<(), Error> {
        crate::dpop::validate_dpop_replay_identity(&self.nonce, &self.capability_id)
            .map_err(invalid)?;
        self.valid_through_unix_secs()?;
        Ok(())
    }
    pub fn valid_through_unix_secs(&self) -> Result<u64, Error> {
        self.issued_at_unix_secs
            .checked_add(self.authority.proof_ttl_secs())
            .filter(|deadline| *deadline <= MAX_UNIX_SECS)
            .ok_or_else(|| invalid("proof horizon exceeds durable clock bounds"))
    }
    pub fn validate_at(&self, authority_time_unix_ms: u64) -> Result<(), Error> {
        self.validate()?;
        if authority_time_unix_ms > super::I_JSON_MAX_SAFE_INTEGER {
            return Err(invalid("authority clock exceeds durable bounds"));
        }
        let seconds = authority_time_unix_ms / 1000;
        if seconds > self.valid_through_unix_secs()?
            || self.issued_at_unix_secs
                > seconds.saturating_add(self.authority.max_clock_skew_secs())
        {
            return Err(invalid("proof is not fresh at the authority clock"));
        }
        Ok(())
    }
    pub fn authority(&self) -> &DpopReplayAuthorityV1 {
        &self.authority
    }
    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
    pub fn invocation_digest(&self) -> &AdmissionDigest {
        &self.invocation_digest
    }
    pub fn proof_digest(&self) -> &AdmissionDigest {
        &self.proof_digest
    }
    pub fn issued_at_unix_secs(&self) -> u64 {
        self.issued_at_unix_secs
    }
}
impl std::fmt::Debug for DpopReplayCredentialV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopReplayCredentialV1")
            .field("proof_digest", &self.proof_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DpopReplayClaimPhase {
    NoncePreflight,
    Dispatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DpopReplayClaimDisposition {
    ReservedBeforeDispatch,
    ReleasedBeforeDispatch,
    RetainedAfterDispatchCommit,
}

/// Prepared claim data from the configured verifier, never caller metadata.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    deny_unknown_fields,
    try_from = "DpopReplayClaimIntentInputV1"
)]
pub struct DpopReplayClaimIntentV1 {
    episode_id: AdmissionIdentifier,
    request_binding_hash: AdmissionDigest,
    grant_index: u32,
    phase: DpopReplayClaimPhase,
    credential: DpopReplayCredentialV1,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DpopReplayClaimIntentInputV1 {
    pub episode_id: AdmissionIdentifier,
    pub request_binding_hash: AdmissionDigest,
    pub grant_index: u32,
    pub phase: DpopReplayClaimPhase,
    pub credential: DpopReplayCredentialV1,
}
impl TryFrom<DpopReplayClaimIntentInputV1> for DpopReplayClaimIntentV1 {
    type Error = Error;
    fn try_from(input: DpopReplayClaimIntentInputV1) -> Result<Self, Error> {
        Self::new(input)
    }
}
impl DpopReplayClaimIntentV1 {
    pub fn new(input: DpopReplayClaimIntentInputV1) -> Result<Self, Error> {
        input.credential.validate()?;
        Ok(Self {
            episode_id: input.episode_id,
            request_binding_hash: input.request_binding_hash,
            grant_index: input.grant_index,
            phase: input.phase,
            credential: input.credential,
        })
    }
    pub fn validate(&self) -> Result<(), Error> {
        self.credential.validate()
    }
    pub fn episode_id(&self) -> &AdmissionIdentifier {
        &self.episode_id
    }
    pub fn request_binding_hash(&self) -> &AdmissionDigest {
        &self.request_binding_hash
    }
    pub fn grant_index(&self) -> u32 {
        self.grant_index
    }
    pub fn phase(&self) -> DpopReplayClaimPhase {
        self.phase
    }
    pub fn credential(&self) -> &DpopReplayCredentialV1 {
        &self.credential
    }
}
impl std::fmt::Debug for DpopReplayClaimIntentV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopReplayClaimIntentV1")
            .field("episode_id", &self.episode_id)
            .field("phase", &self.phase)
            .field("grant_index", &self.grant_index)
            .finish_non_exhaustive()
    }
}

/// Exact history reference. Release still requires the current operation lease.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DpopReplayClaimReferenceV1 {
    operation_id: AdmissionOperationId,
    episode_id: AdmissionIdentifier,
    claim_digest: AdmissionDigest,
}
impl DpopReplayClaimReferenceV1 {
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DpopReplayClaimHistoryV1 {
    pub reference: DpopReplayClaimReferenceV1,
    pub intent: DpopReplayClaimIntentV1,
    pub disposition: DpopReplayClaimDisposition,
}
fn invalid(detail: impl std::fmt::Display) -> Error {
    Error::Invariant(format!("DPoP claim: {detail}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
