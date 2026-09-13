//! The durable proof domain is explicit and signed. It cannot be inferred from
//! a legacy cache, a caller-selected label, or a decoded migration snapshot.
//! These types describe a profile; constructing them does not activate it.

use chio_core::crypto::sha256_hex;
use serde::{Deserialize, Serialize};

use super::{canonical_json_bytes, validate_dpop_replay_identity, verify_dpop_bindings_at};
use super::{CapabilityToken, DpopConfig, DpopProof, KernelError};
use crate::admission_operation::{AdmissionDigest, AdmissionIdentifier};

pub const DPOP_AUTHORITY_SCHEMA: &str = "chio.dpop_proof.v2";
pub const MAX_DURABLE_DPOP_TTL_SECS: u64 = 3600;
pub const MAX_DURABLE_DPOP_CLOCK_SKEW_SECS: u64 = 300;
const MAX_UNIX_SECS: u64 = 9_007_199_254_740;

/// Independently pinned destination, source generation and immutable freshness
/// policy. All fields are included in the agent's proof signature. This bounded
/// wire value is not an activation credential or a replay-store handle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "DpopReplayAuthorityInputV1")]
pub struct DpopReplayAuthorityV1 {
    destination_store_uuid: AdmissionIdentifier,
    dpop_authority_id: AdmissionIdentifier,
    expectation_id: AdmissionDigest,
    proof_ttl_secs: u64,
    max_clock_skew_secs: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpopReplayAuthorityInputV1 {
    pub destination_store_uuid: AdmissionIdentifier,
    pub dpop_authority_id: AdmissionIdentifier,
    pub expectation_id: AdmissionDigest,
    pub proof_ttl_secs: u64,
    pub max_clock_skew_secs: u64,
}

impl TryFrom<DpopReplayAuthorityInputV1> for DpopReplayAuthorityV1 {
    type Error = KernelError;
    fn try_from(input: DpopReplayAuthorityInputV1) -> Result<Self, Self::Error> {
        Self::new(input)
    }
}

impl DpopReplayAuthorityV1 {
    pub fn new(input: DpopReplayAuthorityInputV1) -> Result<Self, KernelError> {
        let value = Self {
            destination_store_uuid: input.destination_store_uuid,
            dpop_authority_id: input.dpop_authority_id,
            expectation_id: input.expectation_id,
            proof_ttl_secs: input.proof_ttl_secs,
            max_clock_skew_secs: input.max_clock_skew_secs,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), KernelError> {
        let store = uuid::Uuid::parse_str(self.destination_store_uuid.as_str())
            .map_err(|_| invalid("destination store UUID is invalid"))?;
        if store.is_nil() || store.to_string() != self.destination_store_uuid.as_str() {
            return Err(invalid("destination store UUID is not canonical"));
        }
        if !(1..=MAX_DURABLE_DPOP_TTL_SECS).contains(&self.proof_ttl_secs)
            || self.max_clock_skew_secs > MAX_DURABLE_DPOP_CLOCK_SKEW_SECS
        {
            return Err(invalid("durable freshness policy exceeds its bounds"));
        }
        Ok(())
    }

    pub fn destination_store_uuid(&self) -> &AdmissionIdentifier {
        &self.destination_store_uuid
    }
    pub fn dpop_authority_id(&self) -> &AdmissionIdentifier {
        &self.dpop_authority_id
    }
    pub fn expectation_id(&self) -> &AdmissionDigest {
        &self.expectation_id
    }
    pub fn proof_ttl_secs(&self) -> u64 {
        self.proof_ttl_secs
    }
    pub fn max_clock_skew_secs(&self) -> u64 {
        self.max_clock_skew_secs
    }

    fn verification_config(&self) -> DpopConfig {
        DpopConfig {
            proof_ttl_secs: self.proof_ttl_secs,
            max_clock_skew_secs: self.max_clock_skew_secs,
            // The shared stateless verifier does not inspect replay capacity.
            // Physical capacity is enforced by the owning durable participant.
            nonce_store_capacity: 0,
        }
    }
}

/// Non-consuming cryptographic verification output. It cannot be decoded,
/// cloned or used as a dispatch permit. Current configured capability, policy,
/// revocation and operation-fenced replay custody are still required.
pub struct VerifiedDpopReplayProof {
    authority: DpopReplayAuthorityV1,
    capability_id: String,
    nonce: String,
    proof_digest: AdmissionDigest,
    invocation_digest: AdmissionDigest,
    issued_at_unix_secs: u64,
    valid_through_unix_secs: u64,
}

impl VerifiedDpopReplayProof {
    pub fn authority(&self) -> &DpopReplayAuthorityV1 {
        &self.authority
    }
    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
    pub fn proof_digest(&self) -> &AdmissionDigest {
        &self.proof_digest
    }
    pub fn invocation_digest(&self) -> &AdmissionDigest {
        &self.invocation_digest
    }
    pub fn issued_at_unix_secs(&self) -> u64 {
        self.issued_at_unix_secs
    }
    pub fn valid_through_unix_secs(&self) -> u64 {
        self.valid_through_unix_secs
    }
}

impl std::fmt::Debug for VerifiedDpopReplayProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedDpopReplayProof")
            .field("proof_digest", &self.proof_digest)
            .finish_non_exhaustive()
    }
}

/// Verify only the explicit v2 profile against independently selected durable
/// authority and a trusted observed clock. Never select authority from the proof
/// itself. This operation does not establish activation or reserve a nonce.
pub fn verify_authority_dpop_proof_stateless(
    proof: &DpopProof,
    capability: &CapabilityToken,
    expected_tool_server: &str,
    expected_tool_name: &str,
    expected_action_hash: &str,
    expected_authority: &DpopReplayAuthorityV1,
    authority_now_unix_secs: u64,
) -> Result<VerifiedDpopReplayProof, KernelError> {
    validate_dpop_replay_identity(&proof.body.nonce, &proof.body.capability_id)?;
    expected_authority.validate()?;
    if proof.body.schema != DPOP_AUTHORITY_SCHEMA
        || proof.body.replay_authority.as_ref() != Some(expected_authority)
    {
        return Err(invalid(
            "proof does not match the independently pinned durable domain",
        ));
    }
    let valid_through = proof
        .body
        .issued_at
        .checked_add(expected_authority.proof_ttl_secs)
        .filter(|deadline| *deadline <= MAX_UNIX_SECS)
        .ok_or_else(|| invalid("proof validity exceeds the durable clock range"))?;
    if authority_now_unix_secs > MAX_UNIX_SECS {
        return Err(invalid("authority clock exceeds the durable clock range"));
    }
    verify_dpop_bindings_at(
        proof,
        capability,
        expected_tool_server,
        expected_tool_name,
        expected_action_hash,
        &expected_authority.verification_config(),
        authority_now_unix_secs,
    )?;
    let bytes = canonical_json_bytes(proof).map_err(|_| invalid("proof encoding failed"))?;
    Ok(VerifiedDpopReplayProof {
        authority: expected_authority.clone(),
        capability_id: proof.body.capability_id.clone(),
        nonce: proof.body.nonce.clone(),
        proof_digest: AdmissionDigest::try_new("dpop_proof", sha256_hex(&bytes))
            .map_err(invalid)?,
        invocation_digest: invocation_binding_digest(
            capability,
            expected_tool_server,
            expected_tool_name,
            expected_action_hash,
        )?,
        issued_at_unix_secs: proof.body.issued_at,
        valid_through_unix_secs: valid_through,
    })
}

/// Non-executable commitment to the proof's sender and invocation fields.
/// Used to compare verified evidence with a credential-redacted retained request.
/// The caller must still verify the capability and the proof's signature.
pub fn invocation_binding_digest(
    capability: &CapabilityToken,
    tool_server: &str,
    tool_name: &str,
    action_hash: &str,
) -> Result<AdmissionDigest, KernelError> {
    let bytes = canonical_json_bytes(&(
        "chio.dpop-invocation-binding.v1",
        &capability.id,
        &capability.subject,
        tool_server,
        tool_name,
        action_hash,
    ))
    .map_err(|_| invalid("invocation binding encoding failed"))?;
    AdmissionDigest::try_new("dpop_invocation", sha256_hex(&bytes)).map_err(invalid)
}

fn invalid(detail: impl std::fmt::Display) -> KernelError {
    KernelError::DpopVerificationFailed(format!("durable DPoP profile: {detail}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
