//! Settlement reads of the signed metadata block `financial`.
//!
//! A reader decodes the whole block into `FinancialBlock`, a closed type with two strict
//! shapes, before it derives the `FinancialSettlementProjection` it acts on. A present block
//! that decodes as neither shape (an unknown member, a missing member or a mixed shape)
//! refuses with `MalformedFinancialMetadata`; only an absent block reads as no settlement.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use core::fmt;

use serde::{de, Deserialize, Deserializer, Serialize};

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
#[serde(try_from = "RetainedAmbiguousWire")]
pub struct RetainedAmbiguousFinancialBlock {
    /// Always `true`; decode refuses `false`.
    pub payment_authorization_ambiguous: bool,
    pub payment_authorization_error_code: PaymentAuthorizationErrorCode,
    /// The durable operation id of the payment attempt; decode refuses an empty reference.
    pub payment_attempt_reference: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedAmbiguousWire {
    payment_authorization_ambiguous: bool,
    payment_authorization_error_code: PaymentAuthorizationErrorCode,
    payment_attempt_reference: String,
}

impl TryFrom<RetainedAmbiguousWire> for RetainedAmbiguousFinancialBlock {
    type Error = &'static str;

    fn try_from(wire: RetainedAmbiguousWire) -> Result<Self, Self::Error> {
        if !wire.payment_authorization_ambiguous {
            return Err("payment_authorization_ambiguous must be true");
        }
        if wire.payment_attempt_reference.is_empty() {
            return Err("payment_attempt_reference must not be empty");
        }
        Ok(Self {
            payment_authorization_ambiguous: true,
            payment_authorization_error_code: wire.payment_authorization_error_code,
            payment_attempt_reference: wire.payment_attempt_reference,
        })
    }
}

/// The complete signed `financial` block, in one of its two shapes. A block carrying
/// `payment_authorization_ambiguous` decodes only as `RetainedAmbiguous`; any other block
/// decodes only as `Charged`.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum FinancialBlock {
    Charged(Box<ChargedFinancialBlock>),
    RetainedAmbiguous(RetainedAmbiguousFinancialBlock),
}

impl<'de> Deserialize<'de> for FinancialBlock {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let block = serde_json::Value::deserialize(deserializer)?;
        let retained = block
            .as_object()
            .is_some_and(|members| members.contains_key("payment_authorization_ambiguous"));
        if retained {
            RetainedAmbiguousFinancialBlock::deserialize(block)
                .map(Self::RetainedAmbiguous)
                .map_err(de::Error::custom)
        } else {
            ChargedFinancialBlock::deserialize(block)
                .map(|charged| Self::Charged(Box::new(charged)))
                .map_err(de::Error::custom)
        }
    }
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

/// A present `financial` block that is not a valid `FinancialBlock`; `detail` is the decode
/// refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MalformedFinancialMetadata {
    pub detail: String,
}

impl fmt::Display for MalformedFinancialMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "malformed financial metadata: {}", self.detail)
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
        Self::deserialize(block)
            .map(Some)
            .map_err(|error| MalformedFinancialMetadata {
                detail: error.to_string(),
            })
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
