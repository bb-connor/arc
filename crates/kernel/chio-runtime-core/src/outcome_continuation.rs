//! Experimental receiver-owned effect slots activated by verified artifact outcomes.
//!
//! Provision rules through a trusted local path. At a protected tool's final
//! dispatch boundary, call `claim_outcome_effect` before performing the effect.
//! The claim is permanent: a crash or ambiguous error cannot release the slot.
//! This gate supplements kernel capability and guard checks; it does not replace
//! them. A selected verifier remains trusted for the truth of its test result.

use chio_core_types::crypto::{canonical_json_bytes, Keypair, PublicKey, Signature};
use serde::{Deserialize, Serialize};

use crate::hash::canonical_sha256;
use crate::validation::{ensure_sha256_hash, rejected, validate_non_empty};
use crate::ChioRuntimeError;

pub const ARTIFACT_OUTCOME_SCHEMA: &str = "chio.runtime.artifact-outcome.experimental.v1";

/// Stable owner-selected identity. No token, session, attempt, evidence digest,
/// or candidate artifact is part of the slot's identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutcomeEffectSlot {
    pub receiver_id: String,
    pub workflow_id: String,
    pub step_id: String,
}

impl OutcomeEffectSlot {
    pub fn sha256(&self) -> Result<String, ChioRuntimeError> {
        self.validate()?;
        canonical_sha256(&("chio.runtime.outcome-effect-slot.experimental.v1", self))
    }

    fn validate(&self) -> Result<(), ChioRuntimeError> {
        for value in [&self.receiver_id, &self.workflow_id, &self.step_id] {
            validate_non_empty(value, "outcome_slot_empty_identity")?;
        }
        Ok(())
    }
}

/// Receiver activation, immutable within a logical slot. The receiver chooses
/// both the verifier key and the exact test contract. Evidence cannot add a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutcomeEffectRule {
    pub slot: OutcomeEffectSlot,
    pub predecessor_step_id: String,
    pub verifier_key: PublicKey,
    pub contract_sha256: String,
    pub server_id: String,
    pub tool_name: String,
    pub resource: String,
    pub valid_from_unix_ms: u64,
    pub valid_until_unix_ms: u64,
}

impl OutcomeEffectRule {
    pub(crate) fn validate(&self) -> Result<(), ChioRuntimeError> {
        self.slot.validate()?;
        for value in [
            &self.predecessor_step_id,
            &self.server_id,
            &self.tool_name,
            &self.resource,
        ] {
            validate_non_empty(value, "outcome_rule_empty_binding")?;
        }
        ensure_sha256_hash(&self.contract_sha256, "outcome_rule_invalid_contract")?;
        if self.valid_from_unix_ms >= self.valid_until_unix_ms {
            return rejected(
                "outcome_rule_invalid_window",
                "activation interval is empty",
            );
        }
        Ok(())
    }

    pub(crate) fn verify(
        &self,
        request: &OutcomeEffectRequest,
        server_id: &str,
        tool_name: &str,
        now_unix_ms: u64,
    ) -> Result<(), ChioRuntimeError> {
        self.validate()?;
        let outcome = &request.evidence.body;
        outcome.validate()?;
        if self.slot != outcome.slot
            || self.predecessor_step_id != outcome.predecessor_step_id
            || self.contract_sha256 != outcome.contract_sha256
            || self.server_id != server_id
            || self.tool_name != tool_name
            || self.resource != request.arguments.resource
            || outcome.artifact_sha256 != request.arguments.artifact_sha256
        {
            return rejected(
                "outcome_effect_binding_mismatch",
                "outcome or effect binding differs from local rule",
            );
        }
        if !outcome.passed {
            return rejected(
                "outcome_contract_failed",
                "artifact did not pass the selected contract",
            );
        }
        if now_unix_ms < self.valid_from_unix_ms
            || now_unix_ms >= self.valid_until_unix_ms
            || outcome.verified_at_unix_ms < self.valid_from_unix_ms
            || outcome.verified_at_unix_ms > now_unix_ms
        {
            return rejected(
                "outcome_effect_expired",
                "outcome or dispatch is outside the activation interval",
            );
        }
        let bytes = canonical_json_bytes(outcome)
            .map_err(|error| ChioRuntimeError::Canonical(error.to_string()))?;
        if !self
            .verifier_key
            .verify_strict(&bytes, &request.evidence.signature)
        {
            return rejected(
                "outcome_signature_invalid",
                "outcome was not signed by the locally selected verifier",
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactOutcome {
    pub schema: String,
    pub slot: OutcomeEffectSlot,
    pub predecessor_step_id: String,
    pub contract_sha256: String,
    pub artifact_sha256: String,
    pub passed: bool,
    pub verified_at_unix_ms: u64,
}

impl ArtifactOutcome {
    fn validate(&self) -> Result<(), ChioRuntimeError> {
        if self.schema != ARTIFACT_OUTCOME_SCHEMA {
            return rejected(
                "outcome_schema_invalid",
                "unsupported artifact outcome schema",
            );
        }
        self.slot.validate()?;
        validate_non_empty(&self.predecessor_step_id, "outcome_predecessor_empty")?;
        ensure_sha256_hash(&self.contract_sha256, "outcome_contract_invalid")?;
        ensure_sha256_hash(&self.artifact_sha256, "outcome_artifact_invalid")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedArtifactOutcome {
    pub body: ArtifactOutcome,
    pub signature: Signature,
}

impl SignedArtifactOutcome {
    /// Signing asserts the verifier actually evaluated the bound artifact under
    /// the selected contract. This constructor does not perform that evaluation.
    pub fn sign(body: ArtifactOutcome, signer: &Keypair) -> Result<Self, ChioRuntimeError> {
        body.validate()?;
        let bytes = canonical_json_bytes(&body)
            .map_err(|error| ChioRuntimeError::Canonical(error.to_string()))?;
        Ok(Self {
            body,
            signature: signer.sign(&bytes),
        })
    }
}

/// Deliberately narrow first effect interface: one artifact and one local
/// resource, with no caller-selected command, path, argument mapping, or budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutcomeEffectArguments {
    pub artifact_sha256: String,
    pub resource: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutcomeEffectRequest {
    pub evidence: SignedArtifactOutcome,
    pub arguments: OutcomeEffectArguments,
}

/// Durable record of the sole dispatch permission. The request identifier is
/// diagnostic and cannot authorize a retry or select another slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutcomeEffectClaim {
    pub slot: OutcomeEffectSlot,
    pub rule_sha256: String,
    pub evidence_sha256: String,
    pub arguments: OutcomeEffectArguments,
    pub request_id: String,
    pub claimed_at_unix_ms: u64,
}

/// Returned only to the trusted dispatcher after the claim commits. It cannot
/// be deserialized from agent input or reconstructed from a stored status.
pub struct OutcomeDispatchPermit {
    pub(crate) slot_sha256: String,
    pub(crate) claim_sha256: String,
    pub(crate) claim: OutcomeEffectClaim,
}

impl OutcomeDispatchPermit {
    #[must_use]
    pub fn claim(&self) -> &OutcomeEffectClaim {
        &self.claim
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "state", deny_unknown_fields)]
pub enum OutcomeEffectState {
    Waiting,
    /// Dispatch was authorized. Its effect is unknown until a result is saved.
    /// Never convert this state back to Waiting on timeout, restart, or retry.
    DispatchClaimed {
        claim: OutcomeEffectClaim,
    },
    /// The trusted tool adapter recorded a result. This is not a kernel receipt
    /// and does not establish external truth against a dishonest tool adapter.
    Completed {
        claim: OutcomeEffectClaim,
        result: serde_json::Value,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutcomeEffectStatus {
    pub revoked: bool,
    pub state: OutcomeEffectState,
}
