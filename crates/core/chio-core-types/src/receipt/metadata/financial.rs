//! Settlement reads of the signed metadata block `financial`.
//!
//! A reader decodes the whole block into `FinancialBlock`, a closed type with two strict
//! shapes, before it derives the `FinancialSettlementProjection` it acts on. A present block
//! that decodes as neither shape (an unknown member, a missing member or a mixed shape)
//! refuses with `MalformedFinancialMetadata`; only an absent block reads as no settlement.

use alloc::boxed::Box;
use alloc::string::String;
use core::fmt;

use serde::{Deserialize, Serialize};

use crate::oracle::OracleConversionEvidence;
use crate::receipt::economics::SettlementStatus;
use crate::receipt::metadata::{MetadataCommitment, FINANCIAL_METADATA_KEY};

/// The `financial` block of a charged receipt: kernel accounting, settlement state and the
/// kernel cost breakdown, with the tool-reported breakdown committed.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChargedFinancialBlock {
    pub grant_index: u32,
    pub cost_charged: u64,
    pub currency: String,
    #[serde(deserialize_with = "Option::deserialize")]
    pub budget_remaining: Option<u64>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub budget_total: Option<u64>,
    pub delegation_depth: u32,
    pub root_budget_holder: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_reference: Option<String>,
    pub settlement_status: SettlementStatus,
    /// Kernel content only: the payment breakdown and the cross-currency note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_breakdown: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oracle_evidence: Option<OracleConversionEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempted_cost: Option<u64>,
    /// `metadata.financial.reported_cost_breakdown`: the tool-reported cost breakdown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported_cost_breakdown: Option<MetadataCommitment>,
}

/// Closed classification of a payment authorization the rail did not confirm.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentAuthorizationErrorCode {
    Unavailable,
    RailError,
    Declined,
    InsufficientFunds,
    OutcomeUnknown,
}

/// The `financial` block of a denied receipt whose payment authorization stayed ambiguous.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedAmbiguousFinancialBlock {
    /// Always `true`.
    pub payment_authorization_ambiguous: bool,
    pub payment_authorization_error_code: PaymentAuthorizationErrorCode,
    /// The durable operation id of the payment attempt.
    pub payment_attempt_reference: String,
}

/// The complete signed `financial` block, in one of its two shapes.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum FinancialBlock {
    Charged(Box<ChargedFinancialBlock>),
    RetainedAmbiguous(RetainedAmbiguousFinancialBlock),
}

/// What a settlement reader may act on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FinancialSettlementProjection {
    Charged {
        cost_charged: u64,
        currency: String,
        settlement_status: SettlementStatus,
        payment_reference: Option<String>,
    },
    RetainedAmbiguous {
        payment_authorization_error_code: PaymentAuthorizationErrorCode,
        payment_attempt_reference: String,
    },
}

/// A present `financial` block that is not a valid `FinancialBlock`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MalformedFinancialMetadata {
    pub reason: &'static str,
}

impl fmt::Display for MalformedFinancialMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "malformed financial metadata: {}", self.reason)
    }
}

impl core::error::Error for MalformedFinancialMetadata {}

impl FinancialBlock {
    /// Decodes the `financial` block of `metadata`. Absent is `Ok(None)`.
    pub fn from_metadata(
        metadata: Option<&serde_json::Value>,
    ) -> Result<Option<Self>, MalformedFinancialMetadata> {
        let Some(block) = metadata.and_then(|metadata| metadata.get(FINANCIAL_METADATA_KEY)) else {
            return Ok(None);
        };
        let decoded = Self::deserialize(block).map_err(|_| MalformedFinancialMetadata {
            reason: "the block is neither a charged nor a retained-ambiguous settlement",
        })?;
        if let Self::RetainedAmbiguous(retained) = &decoded {
            if !retained.payment_authorization_ambiguous {
                return Err(MalformedFinancialMetadata {
                    reason: "a retained-ambiguous block must mark the authorization ambiguous",
                });
            }
            if retained.payment_attempt_reference.is_empty() {
                return Err(MalformedFinancialMetadata {
                    reason: "retained payment requires a payment attempt reference",
                });
            }
        }
        Ok(Some(decoded))
    }

    /// The settlement projection of this block.
    #[must_use]
    pub fn settlement_projection(&self) -> FinancialSettlementProjection {
        match self {
            Self::Charged(charged) => FinancialSettlementProjection::Charged {
                cost_charged: charged.cost_charged,
                currency: charged.currency.clone(),
                settlement_status: charged.settlement_status.clone(),
                payment_reference: charged.payment_reference.clone(),
            },
            Self::RetainedAmbiguous(retained) => FinancialSettlementProjection::RetainedAmbiguous {
                payment_authorization_error_code: retained.payment_authorization_error_code,
                payment_attempt_reference: retained.payment_attempt_reference.clone(),
            },
        }
    }
}

/// The settlement projection of the `financial` block of `metadata`: `Ok(None)` only when the
/// block is absent, `MalformedFinancialMetadata` when a present block is not a
/// `FinancialBlock`.
pub fn financial_settlement_projection(
    metadata: Option<&serde_json::Value>,
) -> Result<Option<FinancialSettlementProjection>, MalformedFinancialMetadata> {
    Ok(FinancialBlock::from_metadata(metadata)?.map(|block| block.settlement_projection()))
}
