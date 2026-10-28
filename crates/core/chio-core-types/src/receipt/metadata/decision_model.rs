//! The `decision_model_witness` receipt-metadata block.
//!
//! The block records which pinned decision model judged a tool call and how
//! the judgement ended. It is a function of the public tuple `(model card
//! digest, artifact digest, outcome, evaluation, fallback reason)` and the
//! artifact's fixed work count, so it carries no argument, result, atom or
//! rule selection, and no margin.

use alloc::format;
use alloc::string::String;

use serde::{Deserialize, Deserializer, Serialize};

use crate::error::{Error, Result};
use crate::receipt::validation::{require_exact, require_lowercase_hex_chars};

/// Decision-model witness metadata block key.
pub const DECISION_MODEL_WITNESS_METADATA_KEY: &str = "decision_model_witness";

/// Schema identifier pinned by every `decision_model_witness` block.
pub const DECISION_MODEL_WITNESS_SCHEMA: &str = "chio.decision-model-witness.v1";

chio_security_types::lossless_serde! {
    /// The decision-model guard's own outcome. A later guard can still deny a
    /// call this guard allowed, so it need not equal the receipt verdict.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
    #[serde(rename_all = "snake_case")]
    pub enum DecisionModelOutcome {
        Allow,
        Hold,
        Deny,
    }
}

chio_security_types::lossless_serde! {
    /// Whether the model evaluated the call or the guard fell back to deny.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
    #[serde(rename_all = "snake_case")]
    pub enum DecisionModelEvaluation {
        Evaluated,
        Fallback,
    }
}

chio_security_types::lossless_serde! {
    /// Why the guard fell back to deny without an evaluation.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
    #[serde(rename_all = "snake_case")]
    pub enum DecisionModelFallbackReason {
        EmptyProposal,
        ProposalInfeasible,
        ScorerError,
        WorkExhausted,
        PolicyUnavailable,
    }
}

/// Decision-model witness, authenticated by the enclosing receipt.
///
/// Decoding is lossless: the decoded value reserializes to the exact input, so
/// a `null` `fallback_reason` or a repeated key is refused rather than
/// normalized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DecisionModelWitness {
    /// Schema identifier; always [`DECISION_MODEL_WITNESS_SCHEMA`].
    pub schema: String,
    /// Canonical lowercase 64-hex digest of the pinned model card.
    pub model_card_digest: String,
    /// Canonical lowercase 64-hex digest of the pinned model artifact.
    pub artifact_digest: String,
    /// The guard's outcome.
    pub outcome: DecisionModelOutcome,
    /// Evaluated, or fell back to deny.
    pub evaluation: DecisionModelEvaluation,
    /// Present exactly when `evaluation` is `fallback`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<DecisionModelFallbackReason>,
    /// Work charged for the evaluation: the artifact's op count when
    /// evaluated, zero on fallback.
    pub work_ops: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct DecisionModelWitnessWire {
    schema: String,
    model_card_digest: String,
    artifact_digest: String,
    outcome: DecisionModelOutcome,
    evaluation: DecisionModelEvaluation,
    #[serde(default)]
    fallback_reason: Option<DecisionModelFallbackReason>,
    work_ops: u32,
}

impl From<DecisionModelWitnessWire> for DecisionModelWitness {
    fn from(wire: DecisionModelWitnessWire) -> Self {
        Self {
            schema: wire.schema,
            model_card_digest: wire.model_card_digest,
            artifact_digest: wire.artifact_digest,
            outcome: wire.outcome,
            evaluation: wire.evaluation,
            fallback_reason: wire.fallback_reason,
            work_ops: wire.work_ops,
        }
    }
}

impl<'de> Deserialize<'de> for DecisionModelWitness {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        chio_security_types::strict_serde::lossless(
            deserializer,
            "DecisionModelWitness",
            |value| serde_json::from_value::<DecisionModelWitnessWire>(value).map(Self::from),
            |witness| serde_json::to_value(witness),
        )
    }
}

impl DecisionModelWitness {
    /// The witness of an evaluated call charged `work_ops`.
    pub fn evaluated(
        model_card_digest: String,
        artifact_digest: String,
        outcome: DecisionModelOutcome,
        work_ops: u32,
    ) -> Result<Self> {
        let witness = Self {
            schema: DECISION_MODEL_WITNESS_SCHEMA.into(),
            model_card_digest,
            artifact_digest,
            outcome,
            evaluation: DecisionModelEvaluation::Evaluated,
            fallback_reason: None,
            work_ops,
        };
        witness.validate()?;
        Ok(witness)
    }

    /// The witness of a fallback deny for `reason`.
    pub fn fallback(
        model_card_digest: String,
        artifact_digest: String,
        reason: DecisionModelFallbackReason,
    ) -> Result<Self> {
        let witness = Self {
            schema: DECISION_MODEL_WITNESS_SCHEMA.into(),
            model_card_digest,
            artifact_digest,
            outcome: DecisionModelOutcome::Deny,
            evaluation: DecisionModelEvaluation::Fallback,
            fallback_reason: Some(reason),
            work_ops: 0,
        };
        witness.validate()?;
        Ok(witness)
    }

    /// Validate the committed fields: the schema is pinned, both digests are
    /// canonical lowercase 64-hex, an evaluated witness has no fallback
    /// reason, and a fallback witness has a reason, outcome `deny` and zero
    /// work.
    pub fn validate(&self) -> Result<()> {
        require_exact(
            &self.schema,
            DECISION_MODEL_WITNESS_SCHEMA,
            "decision_model_witness.schema",
        )?;
        require_lowercase_hex_chars(
            &self.model_card_digest,
            64,
            "decision_model_witness.model_card_digest",
        )?;
        require_lowercase_hex_chars(
            &self.artifact_digest,
            64,
            "decision_model_witness.artifact_digest",
        )?;
        match (self.evaluation, self.fallback_reason) {
            (DecisionModelEvaluation::Evaluated, None) => Ok(()),
            (DecisionModelEvaluation::Evaluated, Some(_)) => {
                Err(malformed("an evaluated witness carries no fallback_reason"))
            }
            (DecisionModelEvaluation::Fallback, None) => {
                Err(malformed("a fallback witness requires a fallback_reason"))
            }
            (DecisionModelEvaluation::Fallback, Some(_)) => {
                if self.outcome != DecisionModelOutcome::Deny {
                    return Err(malformed("a fallback witness has outcome deny"));
                }
                if self.work_ops != 0 {
                    return Err(malformed("a fallback witness has work_ops 0"));
                }
                Ok(())
            }
        }
    }

    /// [`Self::validate`], and the work count against the pinned artifact's
    /// `op_count`: an evaluated witness charged exactly `op_count`.
    pub fn validate_for_artifact(&self, op_count: u32) -> Result<()> {
        self.validate()?;
        if self.evaluation == DecisionModelEvaluation::Evaluated && self.work_ops != op_count {
            return Err(Error::CanonicalJson(format!(
                "decision_model_witness: work_ops {} differs from the artifact op_count {op_count}",
                self.work_ops
            )));
        }
        Ok(())
    }
}

fn malformed(reason: &str) -> Error {
    Error::CanonicalJson(format!("decision_model_witness: {reason}"))
}
