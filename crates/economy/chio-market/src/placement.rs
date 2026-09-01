//! Liability placement, bound-coverage, and auto-bind artifacts.

use serde::{Deserialize, Serialize};

use crate::capability::scope::MonetaryAmount;
use crate::receipt::lineage::SignedExportEnvelope;

use crate::error::MarketError;
use crate::{
    validate_positive_money, LiabilityQuoteDisposition, SignedLiabilityPricingAuthority,
    SignedLiabilityQuoteResponse,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityPlacementArtifact {
    pub schema: String,
    pub placement_id: String,
    pub issued_at: u64,
    pub quote_response: SignedLiabilityQuoteResponse,
    pub selected_coverage_amount: MonetaryAmount,
    pub selected_premium_amount: MonetaryAmount,
    pub effective_from: u64,
    pub effective_until: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl LiabilityPlacementArtifact {
    pub fn validate(&self) -> Result<(), MarketError> {
        if !self.quote_response.verify_signature().map_err(|error| {
            MarketError::signature_invalid(format!(
                "placement quote_response signature verification failed: {error}"
            ))
        })? {
            return Err(MarketError::signature_invalid(
                "placement quote_response signature verification failed",
            ));
        }
        self.quote_response.body.validate()?;
        let quote_request = &self.quote_response.body.quote_request.body;
        let quoted_terms = self
            .quote_response
            .body
            .quoted_terms
            .as_ref()
            .ok_or_else(|| {
                MarketError::state_invalid("placements require a quoted quote response")
            })?;
        if self.quote_response.body.disposition != LiabilityQuoteDisposition::Quoted {
            return Err(MarketError::state_invalid(
                "placements require a quoted quote response",
            ));
        }
        validate_positive_money(
            &self.selected_coverage_amount,
            "placement selected_coverage_amount",
        )?;
        validate_positive_money(
            &self.selected_premium_amount,
            "placement selected_premium_amount",
        )?;
        if self.selected_coverage_amount != quote_request.requested_coverage_amount {
            return Err(MarketError::binding_mismatch(
"placement selected_coverage_amount must match the quote request requested_coverage_amount",
));
        }
        if self.selected_coverage_amount != quoted_terms.quoted_coverage_amount {
            return Err(MarketError::binding_mismatch(
                "placement selected_coverage_amount must match the quoted coverage amount",
            ));
        }
        if self.selected_premium_amount != quoted_terms.quoted_premium_amount {
            return Err(MarketError::binding_mismatch(
                "placement selected_premium_amount must match the quoted premium amount",
            ));
        }
        if self.effective_from != quote_request.requested_effective_from
            || self.effective_until != quote_request.requested_effective_until
        {
            return Err(MarketError::binding_mismatch(
                "placement effective window must match the quote request effective window",
            ));
        }
        if self.effective_until <= self.effective_from {
            return Err(MarketError::window_invalid(
                "placement effective window must have end after start",
            ));
        }
        if self.issued_at >= quoted_terms.expires_at {
            return Err(MarketError::window_invalid(
                "placement cannot be issued after the quote expires",
            ));
        }
        Ok(())
    }
}

pub type SignedLiabilityPlacement = SignedExportEnvelope<LiabilityPlacementArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityBoundCoverageArtifact {
    pub schema: String,
    pub bound_coverage_id: String,
    pub issued_at: u64,
    pub placement: SignedLiabilityPlacement,
    pub policy_number: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carrier_reference: Option<String>,
    pub bound_at: u64,
    pub effective_from: u64,
    pub effective_until: u64,
    pub coverage_amount: MonetaryAmount,
    pub premium_amount: MonetaryAmount,
}

impl LiabilityBoundCoverageArtifact {
    pub fn validate(&self) -> Result<(), MarketError> {
        if !self.placement.verify_signature().map_err(|error| {
            MarketError::signature_invalid(format!(
                "bound coverage placement signature verification failed: {error}"
            ))
        })? {
            return Err(MarketError::signature_invalid(
                "bound coverage placement signature verification failed",
            ));
        }
        self.placement.body.validate()?;
        let quote_request = &self.placement.body.quote_response.body.quote_request.body;
        if self.policy_number.trim().is_empty() {
            return Err(MarketError::field_invalid(
                "bound coverage requires policy_number",
            ));
        }
        if self.bound_at < self.placement.body.issued_at {
            return Err(MarketError::window_invalid(
                "bound coverage bound_at cannot precede placement issuance",
            ));
        }
        if self.effective_from != self.placement.body.effective_from
            || self.effective_until != self.placement.body.effective_until
        {
            return Err(MarketError::binding_mismatch(
                "bound coverage effective window must match the placement effective window",
            ));
        }
        if self.effective_until <= self.effective_from {
            return Err(MarketError::window_invalid(
                "bound coverage effective window must have end after start",
            ));
        }
        if self.coverage_amount != self.placement.body.selected_coverage_amount {
            return Err(MarketError::binding_mismatch(
                "bound coverage coverage_amount must match the placement selected_coverage_amount",
            ));
        }
        if self.premium_amount != self.placement.body.selected_premium_amount {
            return Err(MarketError::binding_mismatch(
                "bound coverage premium_amount must match the placement selected_premium_amount",
            ));
        }
        if !quote_request.provider_policy.bound_coverage_supported {
            return Err(MarketError::state_invalid(
"bound coverage cannot be issued because the provider policy does not support bound coverage",
));
        }
        if !quote_request.provider_policy.claims_supported {
            return Err(MarketError::state_invalid(
"bound coverage cannot be issued because the provider policy does not support claims",
));
        }
        Ok(())
    }
}

pub type SignedLiabilityBoundCoverage = SignedExportEnvelope<LiabilityBoundCoverageArtifact>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityAutoBindDisposition {
    AutoBound,
    ManualReview,
    Denied,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityAutoBindReasonCode {
    AuthorityExpired,
    QuoteExpired,
    AutoBindDisabled,
    CoverageExceedsAuthority,
    PremiumExceedsAuthority,
    CapitalUnavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityAutoBindFinding {
    pub code: LiabilityAutoBindReasonCode,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityAutoBindDecisionArtifact {
    pub schema: String,
    pub decision_id: String,
    pub issued_at: u64,
    pub authority: SignedLiabilityPricingAuthority,
    pub quote_response: SignedLiabilityQuoteResponse,
    pub disposition: LiabilityAutoBindDisposition,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<LiabilityAutoBindFinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement: Option<SignedLiabilityPlacement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_coverage: Option<SignedLiabilityBoundCoverage>,
}

impl LiabilityAutoBindDecisionArtifact {
    pub fn validate(&self) -> Result<(), MarketError> {
        if !self.authority.verify_signature().map_err(|error| {
            MarketError::signature_invalid(format!(
                "auto-bind authority signature verification failed: {error}"
            ))
        })? {
            return Err(MarketError::signature_invalid(
                "auto-bind authority signature verification failed",
            ));
        }
        if !self.quote_response.verify_signature().map_err(|error| {
            MarketError::signature_invalid(format!(
                "auto-bind quote_response signature verification failed: {error}"
            ))
        })? {
            return Err(MarketError::signature_invalid(
                "auto-bind quote_response signature verification failed",
            ));
        }
        self.authority.body.validate()?;
        self.quote_response.body.validate()?;
        if self.authority.body.quote_request.body.quote_request_id
            != self.quote_response.body.quote_request.body.quote_request_id
        {
            return Err(MarketError::binding_mismatch(
"auto-bind authority quote_request_id must match the quote response quote_request_id",
));
        }
        if self.authority.body.provider_policy
            != self.quote_response.body.quote_request.body.provider_policy
        {
            return Err(MarketError::binding_mismatch(
                "auto-bind authority provider_policy must match the quote response provider_policy",
            ));
        }
        match self.disposition {
            LiabilityAutoBindDisposition::AutoBound => {
                let placement = self.placement.as_ref().ok_or_else(|| {
                    MarketError::field_invalid("auto-bound decisions require placement")
                })?;
                let bound_coverage = self.bound_coverage.as_ref().ok_or_else(|| {
                    MarketError::field_invalid("auto-bound decisions require bound_coverage")
                })?;
                if !placement.verify_signature().map_err(|error| {
                    MarketError::signature_invalid(format!(
                        "auto-bind placement signature verification failed: {error}"
                    ))
                })? {
                    return Err(MarketError::signature_invalid(
                        "auto-bind placement signature verification failed",
                    ));
                }
                if !bound_coverage.verify_signature().map_err(|error| {
                    MarketError::signature_invalid(format!(
                        "auto-bind bound coverage signature verification failed: {error}"
                    ))
                })? {
                    return Err(MarketError::signature_invalid(
                        "auto-bind bound coverage signature verification failed",
                    ));
                }
                placement.body.validate()?;
                bound_coverage.body.validate()?;
                if placement.body.quote_response.body != self.quote_response.body {
                    return Err(MarketError::binding_mismatch(
                        "auto-bind placement quote_response must match the decision quote_response",
                    ));
                }
                if bound_coverage.body.placement.body != placement.body {
                    return Err(MarketError::binding_mismatch(
                        "auto-bind bound coverage placement must match the decision placement",
                    ));
                }
            }
            LiabilityAutoBindDisposition::ManualReview | LiabilityAutoBindDisposition::Denied => {
                if self.placement.is_some() || self.bound_coverage.is_some() {
                    return Err(MarketError::state_invalid(
"manual-review and denied auto-bind decisions cannot embed issued placement or bound coverage",
));
                }
            }
        }
        Ok(())
    }
}

pub type SignedLiabilityAutoBindDecision = SignedExportEnvelope<LiabilityAutoBindDecisionArtifact>;
