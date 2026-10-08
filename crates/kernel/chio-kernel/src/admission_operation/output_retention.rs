//! Explicit producer envelope data for financed native durable admission.
//! This profile grants no capture, execution, loan or release authority.
use serde::{Deserialize, Deserializer, Serialize};

#[path = "output_retention/materialization.rs"]
mod materialization;

use super::{AdmissionDigest, AdmissionOperationStoreError, I_JSON_MAX_SAFE_INTEGER};
use crate::tool_outcome::{
    MAX_EVALUATION_STEPS, MAX_RAW_INVOCATION_OUTCOME_BYTES, MAX_RESOLVED_OUTPUT_BYTES,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum NativeOutputRetentionSchema {
    #[serde(rename = "chio.native-output-retention.v1")]
    V1,
}

/// Withhold unavailable output after invocation. Recorded work and charges
/// remain retained; this disposition alone proves neither external success
/// nor absence of an effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum NativeOutputOverflowDisposition {
    #[serde(rename = "output_withheld_after_invocation")]
    OutputWithheldAfterInvocation,
}

/// Limits apply to complete canonical envelopes, including request/context,
/// escaped strings, evidence, signing identity and nested copies. Payload size
/// and streaming limits cannot stand in for these independently priced bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOutputEnvelopeBoundsV1 {
    raw: u64,
    resolved: u64,
    evaluation: u64,
    receipt: u64,
    post_return_steps: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeWire {
    raw: u64,
    resolved: u64,
    evaluation: u64,
    receipt: u64,
    post_return_steps: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NativeOutputRetentionError {
    #[error("native output retention envelope is unsupported")]
    UnsupportedEnvelope,
    #[error("native output retention does not cover the original post-return plan")]
    UnsupportedPlan,
}

impl NativeOutputEnvelopeBoundsV1 {
    pub fn new(
        raw: u64,
        resolved: u64,
        evaluation: u64,
        receipt: u64,
        post_return_steps: u16,
    ) -> Result<Self, NativeOutputRetentionError> {
        let bounds = Self {
            raw,
            resolved,
            evaluation,
            receipt,
            post_return_steps,
        };
        bounds.validate()?;
        Ok(bounds)
    }

    fn validate(&self) -> Result<(), NativeOutputRetentionError> {
        if [self.raw, self.resolved, self.evaluation, self.receipt]
            .into_iter()
            .any(|limit| limit == 0 || limit > I_JSON_MAX_SAFE_INTEGER)
            || self.raw > MAX_RAW_INVOCATION_OUTCOME_BYTES as u64
            || self.resolved > MAX_RESOLVED_OUTPUT_BYTES as u64
            || usize::from(self.post_return_steps) > MAX_EVALUATION_STEPS
            || self.post_return_steps == 0
        {
            return Err(NativeOutputRetentionError::UnsupportedEnvelope);
        }
        Ok(())
    }

    pub const fn raw(&self) -> u64 {
        self.raw
    }
    pub const fn resolved(&self) -> u64 {
        self.resolved
    }
    pub const fn evaluation(&self) -> u64 {
        self.evaluation
    }
    pub const fn receipt(&self) -> u64 {
        self.receipt
    }
    pub const fn post_return_steps(&self) -> u16 {
        self.post_return_steps
    }
}

impl<'de> Deserialize<'de> for NativeOutputEnvelopeBoundsV1 {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        let wire = EnvelopeWire::deserialize(decoder)?;
        Self::new(
            wire.raw,
            wire.resolved,
            wire.evaluation,
            wire.receipt,
            wire.post_return_steps,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// Operator-selected configuration data. Original admission must retain this
/// exact profile and bind its canonical commitment to the operation. An actual
/// native source owner separately verifies its complete phase shapes and funds
/// the full liabilities before capture. Deserialization grants neither role.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOutputRetentionProfileV1 {
    schema: NativeOutputRetentionSchema,
    overflow: NativeOutputOverflowDisposition,
    envelopes: NativeOutputEnvelopeBoundsV1,
}

impl NativeOutputRetentionProfileV1 {
    pub const fn new(envelopes: NativeOutputEnvelopeBoundsV1) -> Self {
        Self {
            schema: NativeOutputRetentionSchema::V1,
            overflow: NativeOutputOverflowDisposition::OutputWithheldAfterInvocation,
            envelopes,
        }
    }

    pub const fn envelopes(&self) -> &NativeOutputEnvelopeBoundsV1 {
        &self.envelopes
    }

    pub(crate) fn validate_original_plan(
        &self,
        step_count: usize,
    ) -> Result<(), NativeOutputRetentionError> {
        self.envelopes.validate()?;
        if step_count == 0 || step_count > usize::from(self.envelopes.post_return_steps) {
            return Err(NativeOutputRetentionError::UnsupportedPlan);
        }
        Ok(())
    }

    /// Pure closed implementation selection as DATA. A native store must use
    /// only the actual retained original and authenticate all phase liabilities
    /// independently. This does not assert a funded producer or live authority.
    pub fn materialization_identity(
        &self,
    ) -> Result<crate::tool_outcome::FrozenEvaluationStepV1, AdmissionOperationStoreError> {
        materialization::materialization_identity(self)
    }

    /// A canonical configuration commitment, not a financing certificate.
    pub fn commitment(&self) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
        let canonical = chio_core::canonical::canonical_json_bytes(self)
            .map_err(|error| AdmissionOperationStoreError::Invariant(error.to_string()))?;
        AdmissionDigest::try_new(
            "native_output_retention_profile",
            chio_core::sha256_hex(&canonical),
        )
        .map_err(Into::into)
    }
}
