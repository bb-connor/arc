pub use arc_appraisal as appraisal;
pub use arc_core_types::{capability, crypto, receipt};
pub use arc_credit as credit;
pub use arc_underwriting as underwriting;

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::capability::MonetaryAmount;
use crate::credit::{
    CapitalBookSourceKind, CapitalExecutionAuthorityStep, CapitalExecutionInstructionAction,
    CapitalExecutionObservation, CapitalExecutionRail, CapitalExecutionReconciledState,
    CapitalExecutionRole, CapitalExecutionWindow, CreditFacilityDisposition,
    CreditFacilityLifecycleState, SignedCapitalBookReport, SignedCapitalExecutionInstruction,
    SignedCreditBond, SignedCreditFacility, SignedCreditLossLifecycle,
    SignedCreditProviderRiskPackage, SignedExposureLedgerReport,
};
use crate::receipt::SignedExportEnvelope;
use crate::underwriting::{
    SignedUnderwritingDecision, UnderwritingBudgetAction, UnderwritingDecisionLifecycleState,
    UnderwritingReviewState,
};

pub const LIABILITY_PROVIDER_ARTIFACT_SCHEMA: &str = "arc.market.provider.v1";
pub const LIABILITY_PROVIDER_LIST_REPORT_SCHEMA: &str = "arc.market.provider-list.v1";
pub const LIABILITY_PROVIDER_RESOLUTION_REPORT_SCHEMA: &str = "arc.market.provider-resolution.v1";
pub const LIABILITY_QUOTE_REQUEST_ARTIFACT_SCHEMA: &str = "arc.market.quote-request.v1";
pub const LIABILITY_QUOTE_RESPONSE_ARTIFACT_SCHEMA: &str = "arc.market.quote-response.v1";
pub const LIABILITY_PRICING_AUTHORITY_ARTIFACT_SCHEMA: &str = "arc.market.pricing-authority.v1";
pub const LIABILITY_PLACEMENT_ARTIFACT_SCHEMA: &str = "arc.market.placement.v1";
pub const LIABILITY_BOUND_COVERAGE_ARTIFACT_SCHEMA: &str = "arc.market.bound-coverage.v1";
pub const LIABILITY_AUTO_BIND_DECISION_ARTIFACT_SCHEMA: &str = "arc.market.auto-bind.v1";
pub const LIABILITY_MARKET_WORKFLOW_REPORT_SCHEMA: &str = "arc.market.workflow-list.v1";
pub const LIABILITY_CLAIM_PACKAGE_ARTIFACT_SCHEMA: &str = "arc.market.claim-package.v1";
pub const LIABILITY_CLAIM_RESPONSE_ARTIFACT_SCHEMA: &str = "arc.market.claim-response.v1";
pub const LIABILITY_CLAIM_DISPUTE_ARTIFACT_SCHEMA: &str = "arc.market.claim-dispute.v1";
pub const LIABILITY_CLAIM_ADJUDICATION_ARTIFACT_SCHEMA: &str = "arc.market.claim-adjudication.v1";
pub const LIABILITY_CLAIM_PAYOUT_INSTRUCTION_ARTIFACT_SCHEMA: &str =
    "arc.market.claim-payout-instruction.v1";
pub const LIABILITY_CLAIM_PAYOUT_RECEIPT_ARTIFACT_SCHEMA: &str =
    "arc.market.claim-payout-receipt.v1";
pub const LIABILITY_CLAIM_SETTLEMENT_INSTRUCTION_ARTIFACT_SCHEMA: &str =
    "arc.market.claim-settlement-instruction.v1";
pub const LIABILITY_CLAIM_SETTLEMENT_RECEIPT_ARTIFACT_SCHEMA: &str =
    "arc.market.claim-settlement-receipt.v1";
pub const LIABILITY_CLAIM_WORKFLOW_REPORT_SCHEMA: &str = "arc.market.claim-workflow-list.v1";
pub const MAX_LIABILITY_PROVIDER_LIST_LIMIT: usize = 100;
pub const MAX_LIABILITY_MARKET_WORKFLOW_LIMIT: usize = 100;
pub const MAX_LIABILITY_CLAIM_WORKFLOW_LIMIT: usize = 100;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityProviderType {
    AdmittedCarrier,
    SurplusLine,
    Captive,
    RiskPool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityCoverageClass {
    ToolExecution,
    DataBreach,
    FinancialLoss,
    ProfessionalLiability,
    RegulatoryResponse,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityEvidenceRequirement {
    BehavioralFeed,
    UnderwritingDecision,
    CreditProviderRiskPackage,
    RuntimeAttestationAppraisal,
    CertificationArtifact,
    CreditBond,
    AuthorizationReviewPack,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityProviderLifecycleState {
    Active,
    Suspended,
    Superseded,
    Retired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityProviderProvenance {
    pub configured_by: String,
    pub configured_at: u64,
    pub source_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityJurisdictionPolicy {
    pub jurisdiction: String,
    pub coverage_classes: Vec<LiabilityCoverageClass>,
    pub supported_currencies: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_evidence: Vec<LiabilityEvidenceRequirement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_coverage_amount: Option<MonetaryAmount>,
    pub claims_supported: bool,
    pub quote_ttl_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityProviderSupportBoundary {
    pub curated_registry_only: bool,
    pub automatic_trust_admission: bool,
    pub permissionless_federation_supported: bool,
    pub bound_coverage_supported: bool,
}

impl Default for LiabilityProviderSupportBoundary {
    fn default() -> Self {
        Self {
            curated_registry_only: true,
            automatic_trust_admission: false,
            permissionless_federation_supported: false,
            bound_coverage_supported: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityProviderReport {
    pub schema: String,
    pub provider_id: String,
    pub display_name: String,
    pub provider_type: LiabilityProviderType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_url: Option<String>,
    pub lifecycle_state: LiabilityProviderLifecycleState,
    pub support_boundary: LiabilityProviderSupportBoundary,
    pub policies: Vec<LiabilityJurisdictionPolicy>,
    pub provenance: LiabilityProviderProvenance,
}

impl LiabilityProviderReport {
    pub fn validate(&self) -> Result<(), String> {
        if self.provider_id.trim().is_empty() {
            return Err("provider_id must not be empty".to_string());
        }
        if self.display_name.trim().is_empty() {
            return Err("display_name must not be empty".to_string());
        }
        if self.provenance.configured_by.trim().is_empty() {
            return Err("provenance.configured_by must not be empty".to_string());
        }
        if self.provenance.source_ref.trim().is_empty() {
            return Err("provenance.source_ref must not be empty".to_string());
        }
        if let Some(provider_url) = self.provider_url.as_deref() {
            if !(provider_url.starts_with("http://") || provider_url.starts_with("https://")) {
                return Err("provider_url must start with http:// or https://".to_string());
            }
        }
        if self.policies.is_empty() {
            return Err("providers require at least one jurisdiction policy".to_string());
        }

        let mut seen_jurisdictions = BTreeSet::new();
        for policy in &self.policies {
            if policy.jurisdiction.trim().is_empty() {
                return Err("jurisdiction policies require a non-empty jurisdiction".to_string());
            }
            let normalized_jurisdiction = policy.jurisdiction.trim().to_ascii_lowercase();
            if !seen_jurisdictions.insert(normalized_jurisdiction) {
                return Err(format!(
                    "provider `{}` defines duplicate jurisdiction policy `{}`",
                    self.provider_id, policy.jurisdiction
                ));
            }
            if policy.coverage_classes.is_empty() {
                return Err(format!(
                    "jurisdiction policy `{}` requires at least one coverage class",
                    policy.jurisdiction
                ));
            }
            if policy.supported_currencies.is_empty() {
                return Err(format!(
                    "jurisdiction policy `{}` requires at least one supported currency",
                    policy.jurisdiction
                ));
            }
            if policy.quote_ttl_seconds == 0 {
                return Err(format!(
                    "jurisdiction policy `{}` requires quote_ttl_seconds greater than zero",
                    policy.jurisdiction
                ));
            }
            let mut seen_coverage = BTreeSet::new();
            for coverage_class in &policy.coverage_classes {
                if !seen_coverage.insert(*coverage_class) {
                    return Err(format!(
                        "jurisdiction policy `{}` defines duplicate coverage class `{:?}`",
                        policy.jurisdiction, coverage_class
                    ));
                }
            }
            let mut seen_currencies = BTreeSet::new();
            for currency in &policy.supported_currencies {
                let normalized_currency = currency.trim().to_ascii_uppercase();
                if normalized_currency.len() != 3
                    || !normalized_currency
                        .chars()
                        .all(|character| character.is_ascii_uppercase())
                {
                    return Err(format!(
                        "jurisdiction policy `{}` contains invalid currency `{}`",
                        policy.jurisdiction, currency
                    ));
                }
                if !seen_currencies.insert(normalized_currency) {
                    return Err(format!(
                        "jurisdiction policy `{}` contains duplicate currency `{}`",
                        policy.jurisdiction, currency
                    ));
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityProviderArtifact {
    pub schema: String,
    pub provider_record_id: String,
    pub issued_at: u64,
    pub lifecycle_state: LiabilityProviderLifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_provider_record_id: Option<String>,
    pub report: LiabilityProviderReport,
}

pub type SignedLiabilityProvider = SignedExportEnvelope<LiabilityProviderArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityProviderListQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_class: Option<LiabilityCoverageClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_state: Option<LiabilityProviderLifecycleState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl Default for LiabilityProviderListQuery {
    fn default() -> Self {
        Self {
            provider_id: None,
            jurisdiction: None,
            coverage_class: None,
            currency: None,
            lifecycle_state: None,
            limit: Some(50),
        }
    }
}

impl LiabilityProviderListQuery {
    #[must_use]
    pub fn limit_or_default(&self) -> usize {
        self.limit
            .unwrap_or(50)
            .clamp(1, MAX_LIABILITY_PROVIDER_LIST_LIMIT)
    }

    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.limit = Some(self.limit_or_default());
        normalized.currency = self
            .currency
            .as_ref()
            .map(|currency| currency.trim().to_ascii_uppercase());
        normalized.jurisdiction = self
            .jurisdiction
            .as_ref()
            .map(|jurisdiction| jurisdiction.trim().to_ascii_lowercase());
        normalized
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityProviderRow {
    pub provider: SignedLiabilityProvider,
    pub lifecycle_state: LiabilityProviderLifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by_provider_record_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityProviderListSummary {
    pub matching_providers: u64,
    pub returned_providers: u64,
    pub active_providers: u64,
    pub suspended_providers: u64,
    pub superseded_providers: u64,
    pub retired_providers: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityProviderListReport {
    pub schema: String,
    pub generated_at: u64,
    pub query: LiabilityProviderListQuery,
    pub summary: LiabilityProviderListSummary,
    pub providers: Vec<LiabilityProviderRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityProviderResolutionQuery {
    pub provider_id: String,
    pub jurisdiction: String,
    pub coverage_class: LiabilityCoverageClass,
    pub currency: String,
}

impl LiabilityProviderResolutionQuery {
    pub fn validate(&self) -> Result<(), String> {
        if self.provider_id.trim().is_empty() {
            return Err("provider_id must not be empty".to_string());
        }
        if self.jurisdiction.trim().is_empty() {
            return Err("jurisdiction must not be empty".to_string());
        }
        let currency = self.currency.trim().to_ascii_uppercase();
        if currency.len() != 3
            || !currency
                .chars()
                .all(|character| character.is_ascii_uppercase())
        {
            return Err("currency must be a three-letter uppercase ISO-style code".to_string());
        }
        Ok(())
    }

    #[must_use]
    pub fn normalized(&self) -> Self {
        Self {
            provider_id: self.provider_id.trim().to_string(),
            jurisdiction: self.jurisdiction.trim().to_ascii_lowercase(),
            coverage_class: self.coverage_class,
            currency: self.currency.trim().to_ascii_uppercase(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityProviderResolutionReport {
    pub schema: String,
    pub generated_at: u64,
    pub query: LiabilityProviderResolutionQuery,
    pub provider: SignedLiabilityProvider,
    pub matched_policy: LiabilityJurisdictionPolicy,
    pub support_boundary: LiabilityProviderSupportBoundary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityQuoteDisposition {
    Quoted,
    Declined,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityProviderPolicyReference {
    pub provider_id: String,
    pub provider_record_id: String,
    pub display_name: String,
    pub jurisdiction: String,
    pub coverage_class: LiabilityCoverageClass,
    pub currency: String,
    pub required_evidence: Vec<LiabilityEvidenceRequirement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_coverage_amount: Option<MonetaryAmount>,
    pub claims_supported: bool,
    pub quote_ttl_seconds: u64,
    pub bound_coverage_supported: bool,
}

impl LiabilityProviderPolicyReference {
    pub fn validate(&self) -> Result<(), String> {
        if self.provider_id.trim().is_empty() {
            return Err("provider policy reference requires provider_id".to_string());
        }
        if self.provider_record_id.trim().is_empty() {
            return Err("provider policy reference requires provider_record_id".to_string());
        }
        if self.display_name.trim().is_empty() {
            return Err("provider policy reference requires display_name".to_string());
        }
        if self.jurisdiction.trim().is_empty() {
            return Err("provider policy reference requires jurisdiction".to_string());
        }
        validate_currency_code(&self.currency, "provider policy reference currency")?;
        if self.quote_ttl_seconds == 0 {
            return Err(
                "provider policy reference requires quote_ttl_seconds greater than zero"
                    .to_string(),
            );
        }
        if let Some(max_coverage_amount) = self.max_coverage_amount.as_ref() {
            if max_coverage_amount.units == 0 {
                return Err(
                    "provider policy reference max_coverage_amount must be greater than zero"
                        .to_string(),
                );
            }
            if max_coverage_amount.currency.trim().to_ascii_uppercase() != self.currency {
                return Err("provider policy reference max_coverage_amount currency must match policy currency".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityPricingAuthorityEnvelopeKind {
    ProviderDelegate,
    RegulatedRole,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityPricingAuthorityEnvelope {
    pub kind: LiabilityPricingAuthorityEnvelopeKind,
    pub delegate_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regulated_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_chain_ref: Option<String>,
}

impl LiabilityPricingAuthorityEnvelope {
    pub fn validate(&self) -> Result<(), String> {
        if self.delegate_id.trim().is_empty() {
            return Err("pricing authority envelope requires delegate_id".to_string());
        }
        if matches!(
            self.kind,
            LiabilityPricingAuthorityEnvelopeKind::RegulatedRole
        ) && self
            .regulated_role
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err(
                "regulated-role pricing authority envelopes require regulated_role".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityQuoteRequestArtifact {
    pub schema: String,
    pub quote_request_id: String,
    pub issued_at: u64,
    pub provider_policy: LiabilityProviderPolicyReference,
    pub requested_coverage_amount: MonetaryAmount,
    pub requested_effective_from: u64,
    pub requested_effective_until: u64,
    pub risk_package: SignedCreditProviderRiskPackage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl LiabilityQuoteRequestArtifact {
    pub fn validate(&self) -> Result<(), String> {
        self.provider_policy.validate()?;
        validate_positive_money(
            &self.requested_coverage_amount,
            "quote request requested_coverage_amount",
        )?;
        if self
            .requested_coverage_amount
            .currency
            .trim()
            .to_ascii_uppercase()
            != self.provider_policy.currency
        {
            return Err(
                "quote request requested_coverage_amount currency must match provider policy currency"
                    .to_string(),
            );
        }
        if self.requested_effective_until <= self.requested_effective_from {
            return Err("quote request effective window must have end after start".to_string());
        }
        if !self.risk_package.verify_signature().map_err(|error| {
            format!("quote request risk package signature verification failed: {error}")
        })? {
            return Err("quote request risk package signature verification failed".to_string());
        }
        if self.risk_package.body.subject_key.trim().is_empty() {
            return Err("quote request risk package subject_key must not be empty".to_string());
        }
        if let Some(max_coverage_amount) = self.provider_policy.max_coverage_amount.as_ref() {
            if self.requested_coverage_amount.units > max_coverage_amount.units {
                return Err(
                    "quote request requested_coverage_amount exceeds provider max_coverage_amount"
                        .to_string(),
                );
            }
        }
        Ok(())
    }
}

pub type SignedLiabilityQuoteRequest = SignedExportEnvelope<LiabilityQuoteRequestArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityQuoteTerms {
    pub quoted_coverage_amount: MonetaryAmount,
    pub quoted_premium_amount: MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quoted_deductible_amount: Option<MonetaryAmount>,
    pub expires_at: u64,
}

impl LiabilityQuoteTerms {
    fn validate_for_request(
        &self,
        request: &LiabilityQuoteRequestArtifact,
        issued_at: u64,
    ) -> Result<(), String> {
        validate_positive_money(
            &self.quoted_coverage_amount,
            "quote response quoted_coverage_amount",
        )?;
        validate_positive_money(
            &self.quoted_premium_amount,
            "quote response quoted_premium_amount",
        )?;
        if let Some(quoted_deductible_amount) = self.quoted_deductible_amount.as_ref() {
            validate_positive_money(
                quoted_deductible_amount,
                "quote response quoted_deductible_amount",
            )?;
            if quoted_deductible_amount
                .currency
                .trim()
                .to_ascii_uppercase()
                != request.provider_policy.currency
            {
                return Err(
                    "quote response quoted_deductible_amount currency must match provider policy currency"
                        .to_string(),
                );
            }
        }
        if self
            .quoted_coverage_amount
            .currency
            .trim()
            .to_ascii_uppercase()
            != request.provider_policy.currency
        {
            return Err(
                "quote response quoted_coverage_amount currency must match provider policy currency"
                    .to_string(),
            );
        }
        if self
            .quoted_premium_amount
            .currency
            .trim()
            .to_ascii_uppercase()
            != request.provider_policy.currency
        {
            return Err(
                "quote response quoted_premium_amount currency must match provider policy currency"
                    .to_string(),
            );
        }
        if self.expires_at <= issued_at {
            return Err("quote response expires_at must be after issuance".to_string());
        }
        if self.expires_at
            > request
                .issued_at
                .saturating_add(request.provider_policy.quote_ttl_seconds)
        {
            return Err("quote response expires_at exceeds provider policy quote TTL".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityQuoteResponseArtifact {
    pub schema: String,
    pub quote_response_id: String,
    pub issued_at: u64,
    pub quote_request: SignedLiabilityQuoteRequest,
    pub provider_quote_ref: String,
    pub disposition: LiabilityQuoteDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_quote_response_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quoted_terms: Option<LiabilityQuoteTerms>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decline_reason: Option<String>,
}

impl LiabilityQuoteResponseArtifact {
    pub fn validate(&self) -> Result<(), String> {
        if !self.quote_request.verify_signature().map_err(|error| {
            format!("quote response quote_request signature verification failed: {error}")
        })? {
            return Err("quote response quote_request signature verification failed".to_string());
        }
        self.quote_request.body.validate()?;
        if self.provider_quote_ref.trim().is_empty() {
            return Err("quote response requires provider_quote_ref".to_string());
        }
        match self.disposition {
            LiabilityQuoteDisposition::Quoted => {
                let quoted_terms = self
                    .quoted_terms
                    .as_ref()
                    .ok_or_else(|| "quoted quote responses require quoted_terms".to_string())?;
                quoted_terms.validate_for_request(&self.quote_request.body, self.issued_at)?;
                if self.decline_reason.is_some() {
                    return Err("quoted quote responses cannot include decline_reason".to_string());
                }
            }
            LiabilityQuoteDisposition::Declined => {
                if self.quoted_terms.is_some() {
                    return Err("declined quote responses cannot include quoted_terms".to_string());
                }
                if self
                    .decline_reason
                    .as_deref()
                    .is_none_or(|value| value.trim().is_empty())
                {
                    return Err("declined quote responses require decline_reason".to_string());
                }
            }
        }
        Ok(())
    }
}

pub type SignedLiabilityQuoteResponse = SignedExportEnvelope<LiabilityQuoteResponseArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityPricingAuthorityArtifact {
    pub schema: String,
    pub authority_id: String,
    pub issued_at: u64,
    pub quote_request: SignedLiabilityQuoteRequest,
    pub provider_policy: LiabilityProviderPolicyReference,
    pub facility: SignedCreditFacility,
    pub underwriting_decision: SignedUnderwritingDecision,
    pub capital_book: SignedCapitalBookReport,
    pub envelope: LiabilityPricingAuthorityEnvelope,
    pub max_coverage_amount: MonetaryAmount,
    pub max_premium_amount: MonetaryAmount,
    pub expires_at: u64,
    pub auto_bind_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl LiabilityPricingAuthorityArtifact {
    pub fn validate(&self) -> Result<(), String> {
        if !self.quote_request.verify_signature().map_err(|error| {
            format!("pricing authority quote_request signature verification failed: {error}")
        })? {
            return Err(
                "pricing authority quote_request signature verification failed".to_string(),
            );
        }
        if !self.facility.verify_signature().map_err(|error| {
            format!("pricing authority facility signature verification failed: {error}")
        })? {
            return Err("pricing authority facility signature verification failed".to_string());
        }
        if !self.underwriting_decision.verify_signature().map_err(|error| {
            format!("pricing authority underwriting decision signature verification failed: {error}")
        })? {
            return Err(
                "pricing authority underwriting decision signature verification failed"
                    .to_string(),
            );
        }
        if !self.capital_book.verify_signature().map_err(|error| {
            format!("pricing authority capital book signature verification failed: {error}")
        })? {
            return Err("pricing authority capital book signature verification failed".to_string());
        }
        self.quote_request.body.validate()?;
        self.provider_policy.validate()?;
        self.envelope.validate()?;
        if self.provider_policy != self.quote_request.body.provider_policy {
            return Err(
                "pricing authority provider_policy must match the quote request provider_policy"
                    .to_string(),
            );
        }
        validate_positive_money(
            &self.max_coverage_amount,
            "pricing authority max_coverage_amount",
        )?;
        validate_positive_money(
            &self.max_premium_amount,
            "pricing authority max_premium_amount",
        )?;
        if self
            .max_coverage_amount
            .currency
            .trim()
            .to_ascii_uppercase()
            != self.provider_policy.currency
        {
            return Err(
                "pricing authority max_coverage_amount currency must match provider policy currency"
                    .to_string(),
            );
        }
        if self.max_premium_amount.currency.trim().to_ascii_uppercase()
            != self.provider_policy.currency
        {
            return Err(
                "pricing authority max_premium_amount currency must match provider policy currency"
                    .to_string(),
            );
        }
        if self.expires_at <= self.issued_at {
            return Err("pricing authority expires_at must be after issuance".to_string());
        }
        if self.expires_at
            > self
                .quote_request
                .body
                .issued_at
                .saturating_add(self.provider_policy.quote_ttl_seconds)
        {
            return Err(
                "pricing authority expires_at exceeds provider policy quote TTL".to_string(),
            );
        }
        if self.facility.body.lifecycle_state != CreditFacilityLifecycleState::Active {
            return Err("pricing authority requires an active facility".to_string());
        }
        if self.facility.body.report.disposition != CreditFacilityDisposition::Grant {
            return Err("pricing authority requires a granted facility".to_string());
        }
        let facility_terms = self
            .facility
            .body
            .report
            .terms
            .as_ref()
            .ok_or_else(|| "pricing authority requires facility terms".to_string())?;
        if facility_terms
            .credit_limit
            .currency
            .trim()
            .to_ascii_uppercase()
            != self.provider_policy.currency
        {
            return Err(
                "pricing authority facility credit limit currency must match provider policy currency"
                    .to_string(),
            );
        }
        if self.max_coverage_amount.units > facility_terms.credit_limit.units {
            return Err(
                "pricing authority max_coverage_amount exceeds facility credit limit".to_string(),
            );
        }
        if let Some(max_coverage_amount) = self.provider_policy.max_coverage_amount.as_ref() {
            if self.max_coverage_amount.units > max_coverage_amount.units {
                return Err(
                    "pricing authority max_coverage_amount exceeds provider max_coverage_amount"
                        .to_string(),
                );
            }
        }
        if self.underwriting_decision.body.lifecycle_state
            != UnderwritingDecisionLifecycleState::Active
        {
            return Err("pricing authority requires an active underwriting decision".to_string());
        }
        if self.underwriting_decision.body.review_state != UnderwritingReviewState::Approved {
            return Err("pricing authority requires an approved underwriting decision".to_string());
        }
        if matches!(
            self.underwriting_decision.body.budget.action,
            UnderwritingBudgetAction::Hold | UnderwritingBudgetAction::Deny
        ) {
            return Err(
                "pricing authority requires underwriting budget action preserve or reduce"
                    .to_string(),
            );
        }
        if let Some(quoted_amount) = self
            .underwriting_decision
            .body
            .premium
            .quoted_amount
            .as_ref()
        {
            if quoted_amount.currency.trim().to_ascii_uppercase() != self.provider_policy.currency {
                return Err(
                    "pricing authority underwriting premium currency must match provider policy currency"
                        .to_string(),
                );
            }
            if self.max_premium_amount.units > quoted_amount.units {
                return Err(
                    "pricing authority max_premium_amount exceeds underwriting quoted premium"
                        .to_string(),
                );
            }
        }
        let subject_key = self
            .quote_request
            .body
            .risk_package
            .body
            .subject_key
            .as_str();
        if self.capital_book.body.subject_key != subject_key {
            return Err(
                "pricing authority capital book subject must match the quote request subject"
                    .to_string(),
            );
        }
        if self.capital_book.body.summary.mixed_currency_book {
            return Err(
                "pricing authority cannot be issued against a mixed-currency capital book"
                    .to_string(),
            );
        }
        let facility_source = self
            .capital_book
            .body
            .sources
            .iter()
            .find(|source| {
                source.facility_id.as_deref() == Some(self.facility.body.facility_id.as_str())
            })
            .ok_or_else(|| {
                "pricing authority capital book must include the referenced facility source"
                    .to_string()
            })?;
        if facility_source.currency.trim().to_ascii_uppercase() != self.provider_policy.currency {
            return Err(
                "pricing authority capital book source currency must match provider policy currency"
                    .to_string(),
            );
        }
        if let Some(committed_amount) = facility_source.committed_amount.as_ref() {
            let available_units = committed_amount
                .units
                .saturating_sub(
                    facility_source
                        .disbursed_amount
                        .as_ref()
                        .map_or(0, |amount| amount.units),
                )
                .saturating_sub(
                    facility_source
                        .impaired_amount
                        .as_ref()
                        .map_or(0, |amount| amount.units),
                );
            if self.max_coverage_amount.units > available_units {
                return Err(
                    "pricing authority max_coverage_amount exceeds capital book available committed amount"
                        .to_string(),
                );
            }
        }
        if self.auto_bind_enabled
            && (!self.provider_policy.bound_coverage_supported
                || !self.provider_policy.claims_supported)
        {
            return Err(
                "pricing authority cannot enable auto_bind because the provider policy does not support bound coverage and claims"
                    .to_string(),
            );
        }
        Ok(())
    }
}

pub type SignedLiabilityPricingAuthority = SignedExportEnvelope<LiabilityPricingAuthorityArtifact>;

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
    pub fn validate(&self) -> Result<(), String> {
        if !self.quote_response.verify_signature().map_err(|error| {
            format!("placement quote_response signature verification failed: {error}")
        })? {
            return Err("placement quote_response signature verification failed".to_string());
        }
        self.quote_response.body.validate()?;
        let quote_request = &self.quote_response.body.quote_request.body;
        let quoted_terms = self
            .quote_response
            .body
            .quoted_terms
            .as_ref()
            .ok_or_else(|| "placements require a quoted quote response".to_string())?;
        if self.quote_response.body.disposition != LiabilityQuoteDisposition::Quoted {
            return Err("placements require a quoted quote response".to_string());
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
            return Err(
                "placement selected_coverage_amount must match the quote request requested_coverage_amount"
                    .to_string(),
            );
        }
        if self.selected_coverage_amount != quoted_terms.quoted_coverage_amount {
            return Err(
                "placement selected_coverage_amount must match the quoted coverage amount"
                    .to_string(),
            );
        }
        if self.selected_premium_amount != quoted_terms.quoted_premium_amount {
            return Err(
                "placement selected_premium_amount must match the quoted premium amount"
                    .to_string(),
            );
        }
        if self.effective_from != quote_request.requested_effective_from
            || self.effective_until != quote_request.requested_effective_until
        {
            return Err(
                "placement effective window must match the quote request effective window"
                    .to_string(),
            );
        }
        if self.effective_until <= self.effective_from {
            return Err("placement effective window must have end after start".to_string());
        }
        if self.issued_at > quoted_terms.expires_at {
            return Err("placement cannot be issued after the quote expires".to_string());
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
    pub fn validate(&self) -> Result<(), String> {
        if !self.placement.verify_signature().map_err(|error| {
            format!("bound coverage placement signature verification failed: {error}")
        })? {
            return Err("bound coverage placement signature verification failed".to_string());
        }
        self.placement.body.validate()?;
        let quote_request = &self.placement.body.quote_response.body.quote_request.body;
        if self.policy_number.trim().is_empty() {
            return Err("bound coverage requires policy_number".to_string());
        }
        if self.bound_at < self.placement.body.issued_at {
            return Err("bound coverage bound_at cannot precede placement issuance".to_string());
        }
        if self.effective_from != self.placement.body.effective_from
            || self.effective_until != self.placement.body.effective_until
        {
            return Err(
                "bound coverage effective window must match the placement effective window"
                    .to_string(),
            );
        }
        if self.effective_until <= self.effective_from {
            return Err("bound coverage effective window must have end after start".to_string());
        }
        if self.coverage_amount != self.placement.body.selected_coverage_amount {
            return Err(
                "bound coverage coverage_amount must match the placement selected_coverage_amount"
                    .to_string(),
            );
        }
        if self.premium_amount != self.placement.body.selected_premium_amount {
            return Err(
                "bound coverage premium_amount must match the placement selected_premium_amount"
                    .to_string(),
            );
        }
        if !quote_request.provider_policy.bound_coverage_supported {
            return Err(
                "bound coverage cannot be issued because the provider policy does not support bound coverage"
                    .to_string(),
            );
        }
        if !quote_request.provider_policy.claims_supported {
            return Err(
                "bound coverage cannot be issued because the provider policy does not support claims"
                    .to_string(),
            );
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
    pub fn validate(&self) -> Result<(), String> {
        if !self.authority.verify_signature().map_err(|error| {
            format!("auto-bind authority signature verification failed: {error}")
        })? {
            return Err("auto-bind authority signature verification failed".to_string());
        }
        if !self.quote_response.verify_signature().map_err(|error| {
            format!("auto-bind quote_response signature verification failed: {error}")
        })? {
            return Err("auto-bind quote_response signature verification failed".to_string());
        }
        self.authority.body.validate()?;
        self.quote_response.body.validate()?;
        if self.authority.body.quote_request.body.quote_request_id
            != self.quote_response.body.quote_request.body.quote_request_id
        {
            return Err(
                "auto-bind authority quote_request_id must match the quote response quote_request_id"
                    .to_string(),
            );
        }
        if self.authority.body.provider_policy
            != self.quote_response.body.quote_request.body.provider_policy
        {
            return Err(
                "auto-bind authority provider_policy must match the quote response provider_policy"
                    .to_string(),
            );
        }
        match self.disposition {
            LiabilityAutoBindDisposition::AutoBound => {
                let placement = self
                    .placement
                    .as_ref()
                    .ok_or_else(|| "auto-bound decisions require placement".to_string())?;
                let bound_coverage = self
                    .bound_coverage
                    .as_ref()
                    .ok_or_else(|| "auto-bound decisions require bound_coverage".to_string())?;
                if !placement.verify_signature().map_err(|error| {
                    format!("auto-bind placement signature verification failed: {error}")
                })? {
                    return Err("auto-bind placement signature verification failed".to_string());
                }
                if !bound_coverage.verify_signature().map_err(|error| {
                    format!("auto-bind bound coverage signature verification failed: {error}")
                })? {
                    return Err(
                        "auto-bind bound coverage signature verification failed".to_string()
                    );
                }
                placement.body.validate()?;
                bound_coverage.body.validate()?;
                if placement.body.quote_response.body != self.quote_response.body {
                    return Err(
                        "auto-bind placement quote_response must match the decision quote_response"
                            .to_string(),
                    );
                }
                if bound_coverage.body.placement.body != placement.body {
                    return Err(
                        "auto-bind bound coverage placement must match the decision placement"
                            .to_string(),
                    );
                }
            }
            LiabilityAutoBindDisposition::ManualReview | LiabilityAutoBindDisposition::Denied => {
                if self.placement.is_some() || self.bound_coverage.is_some() {
                    return Err(
                        "manual-review and denied auto-bind decisions cannot embed issued placement or bound coverage"
                            .to_string(),
                    );
                }
            }
        }
        Ok(())
    }
}

pub type SignedLiabilityAutoBindDecision = SignedExportEnvelope<LiabilityAutoBindDecisionArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityMarketWorkflowQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_class: Option<LiabilityCoverageClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl Default for LiabilityMarketWorkflowQuery {
    fn default() -> Self {
        Self {
            quote_request_id: None,
            provider_id: None,
            agent_subject: None,
            jurisdiction: None,
            coverage_class: None,
            currency: None,
            limit: Some(50),
        }
    }
}

impl LiabilityMarketWorkflowQuery {
    #[must_use]
    pub fn limit_or_default(&self) -> usize {
        self.limit
            .unwrap_or(50)
            .clamp(1, MAX_LIABILITY_MARKET_WORKFLOW_LIMIT)
    }

    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.limit = Some(self.limit_or_default());
        normalized.provider_id = self
            .provider_id
            .as_ref()
            .map(|value| value.trim().to_string());
        normalized.quote_request_id = self
            .quote_request_id
            .as_ref()
            .map(|value| value.trim().to_string());
        normalized.agent_subject = self
            .agent_subject
            .as_ref()
            .map(|value| value.trim().to_string());
        normalized.jurisdiction = self
            .jurisdiction
            .as_ref()
            .map(|value| value.trim().to_ascii_lowercase());
        normalized.currency = self
            .currency
            .as_ref()
            .map(|value| value.trim().to_ascii_uppercase());
        normalized
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityMarketWorkflowRow {
    pub quote_request: SignedLiabilityQuoteRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_quote_response: Option<SignedLiabilityQuoteResponse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pricing_authority: Option<SignedLiabilityPricingAuthority>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_auto_bind_decision: Option<SignedLiabilityAutoBindDecision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement: Option<SignedLiabilityPlacement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_coverage: Option<SignedLiabilityBoundCoverage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityMarketWorkflowSummary {
    pub matching_requests: u64,
    pub returned_requests: u64,
    pub quote_responses: u64,
    pub quoted_responses: u64,
    pub declined_responses: u64,
    pub pricing_authorities: u64,
    pub auto_bind_decisions: u64,
    pub auto_bound_decisions: u64,
    pub manual_review_decisions: u64,
    pub denied_decisions: u64,
    pub placements: u64,
    pub bound_coverages: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityMarketWorkflowReport {
    pub schema: String,
    pub generated_at: u64,
    pub query: LiabilityMarketWorkflowQuery,
    pub summary: LiabilityMarketWorkflowSummary,
    pub workflows: Vec<LiabilityMarketWorkflowRow>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityClaimEvidenceKind {
    BoundCoverage,
    ExposureLedger,
    CreditBond,
    CreditLossLifecycle,
    Receipt,
    ClaimResponse,
    ClaimDispute,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimEvidenceReference {
    pub kind: LiabilityClaimEvidenceKind,
    pub reference_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityClaimResponseDisposition {
    Acknowledged,
    Accepted,
    Denied,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityClaimAdjudicationOutcome {
    ClaimUpheld,
    ProviderUpheld,
    PartialSettlement,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimPackageArtifact {
    pub schema: String,
    pub claim_id: String,
    pub issued_at: u64,
    pub bound_coverage: SignedLiabilityBoundCoverage,
    pub exposure: SignedExposureLedgerReport,
    pub bond: SignedCreditBond,
    pub loss_event: SignedCreditLossLifecycle,
    pub claimant: String,
    pub claim_event_at: u64,
    pub claim_amount: MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_ref: Option<String>,
    pub narrative: String,
    pub receipt_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<LiabilityClaimEvidenceReference>,
}

impl LiabilityClaimPackageArtifact {
    pub fn validate(&self) -> Result<(), String> {
        if self.claimant.trim().is_empty() {
            return Err("claim packages require a non-empty claimant".to_string());
        }
        if self.narrative.trim().is_empty() {
            return Err("claim packages require a non-empty narrative".to_string());
        }
        if self.receipt_ids.is_empty() {
            return Err("claim packages require at least one receipt reference".to_string());
        }
        let mut deduped_receipts = BTreeSet::new();
        for receipt_id in &self.receipt_ids {
            if receipt_id.trim().is_empty() {
                return Err("claim receipt references must be non-empty".to_string());
            }
            if !deduped_receipts.insert(receipt_id.trim().to_string()) {
                return Err("claim receipt references must be unique".to_string());
            }
        }
        validate_positive_money(&self.claim_amount, "claim_amount")?;
        let coverage = &self.bound_coverage.body.coverage_amount;
        if self.claim_amount.currency != coverage.currency {
            return Err("claim_amount currency must match bound coverage currency".to_string());
        }
        if self.claim_amount.units > coverage.units {
            return Err("claim_amount cannot exceed bound coverage amount".to_string());
        }
        if self.claim_event_at < self.bound_coverage.body.effective_from
            || self.claim_event_at > self.bound_coverage.body.effective_until
        {
            return Err(
                "claim_event_at must fall within the bound coverage effective window".to_string(),
            );
        }
        if self.exposure.body.summary.mixed_currency_book {
            return Err(
                "claim packages require exposure evidence without mixed-currency ambiguity"
                    .to_string(),
            );
        }
        let subject_key = &self
            .bound_coverage
            .body
            .placement
            .body
            .quote_response
            .body
            .quote_request
            .body
            .risk_package
            .body
            .subject_key;
        if self
            .exposure
            .body
            .filters
            .agent_subject
            .as_ref()
            .is_some_and(|agent_subject| agent_subject != subject_key)
        {
            return Err(
                "claim exposure evidence must match the bound coverage subject".to_string(),
            );
        }
        if self
            .bond
            .body
            .report
            .filters
            .agent_subject
            .as_ref()
            .is_some_and(|agent_subject| agent_subject != subject_key)
        {
            return Err("claim bond evidence must match the bound coverage subject".to_string());
        }
        if self.loss_event.body.bond_id != self.bond.body.bond_id {
            return Err("claim loss evidence must reference the same bond".to_string());
        }
        if self
            .loss_event
            .body
            .report
            .summary
            .agent_subject
            .as_ref()
            .is_some_and(|agent_subject| agent_subject != subject_key)
        {
            return Err("claim loss evidence must match the bound coverage subject".to_string());
        }
        Ok(())
    }
}

pub type SignedLiabilityClaimPackage = SignedExportEnvelope<LiabilityClaimPackageArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimResponseArtifact {
    pub schema: String,
    pub claim_response_id: String,
    pub issued_at: u64,
    pub claim: SignedLiabilityClaimPackage,
    pub provider_response_ref: String,
    pub disposition: LiabilityClaimResponseDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covered_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denial_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<LiabilityClaimEvidenceReference>,
}

impl LiabilityClaimResponseArtifact {
    pub fn validate(&self) -> Result<(), String> {
        self.claim.body.validate()?;
        if self.provider_response_ref.trim().is_empty() {
            return Err("claim responses require a non-empty provider_response_ref".to_string());
        }
        match self.disposition {
            LiabilityClaimResponseDisposition::Acknowledged => {
                if self.covered_amount.is_some() {
                    return Err(
                        "acknowledged claim responses cannot include covered_amount".to_string()
                    );
                }
                if self.denial_reason.is_some() {
                    return Err(
                        "acknowledged claim responses cannot include denial_reason".to_string()
                    );
                }
            }
            LiabilityClaimResponseDisposition::Accepted => {
                let covered_amount = self
                    .covered_amount
                    .as_ref()
                    .ok_or_else(|| "accepted claim responses require covered_amount".to_string())?;
                validate_positive_money(covered_amount, "covered_amount")?;
                if covered_amount.currency != self.claim.body.claim_amount.currency {
                    return Err(
                        "covered_amount currency must match claim_amount currency".to_string()
                    );
                }
                if covered_amount.units > self.claim.body.claim_amount.units {
                    return Err("covered_amount cannot exceed claim_amount".to_string());
                }
                if self.denial_reason.is_some() {
                    return Err("accepted claim responses cannot include denial_reason".to_string());
                }
            }
            LiabilityClaimResponseDisposition::Denied => {
                if self.covered_amount.is_some() {
                    return Err("denied claim responses cannot include covered_amount".to_string());
                }
                if self
                    .denial_reason
                    .as_ref()
                    .is_none_or(|reason| reason.trim().is_empty())
                {
                    return Err("denied claim responses require denial_reason".to_string());
                }
            }
        }
        Ok(())
    }
}

pub type SignedLiabilityClaimResponse = SignedExportEnvelope<LiabilityClaimResponseArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimDisputeArtifact {
    pub schema: String,
    pub dispute_id: String,
    pub issued_at: u64,
    pub provider_response: SignedLiabilityClaimResponse,
    pub opened_by: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<LiabilityClaimEvidenceReference>,
}

impl LiabilityClaimDisputeArtifact {
    pub fn validate(&self) -> Result<(), String> {
        self.provider_response.body.validate()?;
        if self.opened_by.trim().is_empty() {
            return Err("claim disputes require a non-empty opened_by".to_string());
        }
        if self.reason.trim().is_empty() {
            return Err("claim disputes require a non-empty reason".to_string());
        }
        let partially_accepted = self.provider_response.body.disposition
            == LiabilityClaimResponseDisposition::Accepted
            && self
                .provider_response
                .body
                .covered_amount
                .as_ref()
                .is_some_and(|amount| {
                    amount.units < self.provider_response.body.claim.body.claim_amount.units
                });
        if self.provider_response.body.disposition != LiabilityClaimResponseDisposition::Denied
            && !partially_accepted
        {
            return Err(
                "claim disputes require a denied or partially accepted provider response"
                    .to_string(),
            );
        }
        Ok(())
    }
}

pub type SignedLiabilityClaimDispute = SignedExportEnvelope<LiabilityClaimDisputeArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimAdjudicationArtifact {
    pub schema: String,
    pub adjudication_id: String,
    pub issued_at: u64,
    pub dispute: SignedLiabilityClaimDispute,
    pub adjudicator: String,
    pub outcome: LiabilityClaimAdjudicationOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub awarded_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<LiabilityClaimEvidenceReference>,
}

impl LiabilityClaimAdjudicationArtifact {
    pub fn validate(&self) -> Result<(), String> {
        self.dispute.body.validate()?;
        if self.adjudicator.trim().is_empty() {
            return Err("claim adjudications require a non-empty adjudicator".to_string());
        }
        let claim_amount = &self
            .dispute
            .body
            .provider_response
            .body
            .claim
            .body
            .claim_amount;
        match self.outcome {
            LiabilityClaimAdjudicationOutcome::ClaimUpheld => {
                let awarded_amount = self.awarded_amount.as_ref().ok_or_else(|| {
                    "claim_upheld adjudications require awarded_amount".to_string()
                })?;
                validate_positive_money(awarded_amount, "awarded_amount")?;
                if awarded_amount.currency != claim_amount.currency {
                    return Err(
                        "awarded_amount currency must match claim_amount currency".to_string()
                    );
                }
                if awarded_amount.units > claim_amount.units {
                    return Err("awarded_amount cannot exceed claim_amount".to_string());
                }
            }
            LiabilityClaimAdjudicationOutcome::ProviderUpheld => {
                if self.awarded_amount.is_some() {
                    return Err(
                        "provider_upheld adjudications cannot include awarded_amount".to_string(),
                    );
                }
            }
            LiabilityClaimAdjudicationOutcome::PartialSettlement => {
                let awarded_amount = self.awarded_amount.as_ref().ok_or_else(|| {
                    "partial_settlement adjudications require awarded_amount".to_string()
                })?;
                validate_positive_money(awarded_amount, "awarded_amount")?;
                if awarded_amount.currency != claim_amount.currency {
                    return Err(
                        "awarded_amount currency must match claim_amount currency".to_string()
                    );
                }
                if awarded_amount.units >= claim_amount.units {
                    return Err(
                        "partial_settlement awarded_amount must be less than claim_amount"
                            .to_string(),
                    );
                }
            }
        }
        Ok(())
    }
}

pub type SignedLiabilityClaimAdjudication =
    SignedExportEnvelope<LiabilityClaimAdjudicationArtifact>;

fn liability_claim_adjudication_payable_amount(
    adjudication: &LiabilityClaimAdjudicationArtifact,
) -> Result<&MonetaryAmount, String> {
    match adjudication.outcome {
        LiabilityClaimAdjudicationOutcome::ClaimUpheld
        | LiabilityClaimAdjudicationOutcome::PartialSettlement => {
            adjudication.awarded_amount.as_ref().ok_or_else(|| {
                "claim payout instructions require adjudications with awarded_amount".to_string()
            })
        }
        LiabilityClaimAdjudicationOutcome::ProviderUpheld => {
            Err("claim payout instructions require a payable adjudication outcome".to_string())
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityClaimPayoutReconciliationState {
    Matched,
    AmountMismatch,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityClaimSettlementKind {
    RecoveryClearing,
    ReinsuranceReimbursement,
    FacilityReimbursement,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityClaimSettlementReconciliationState {
    Matched,
    AmountMismatch,
    CounterpartyMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimSettlementRoleBinding {
    pub role: CapitalExecutionRole,
    pub party_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl LiabilityClaimSettlementRoleBinding {
    fn validate(&self, field_name: &str) -> Result<(), String> {
        if self.party_id.trim().is_empty() {
            return Err(format!("{field_name} requires a non-empty party_id"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimSettlementRoleTopology {
    pub payer: LiabilityClaimSettlementRoleBinding,
    pub payee: LiabilityClaimSettlementRoleBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beneficiary: Option<LiabilityClaimSettlementRoleBinding>,
}

impl LiabilityClaimSettlementRoleTopology {
    fn validate(&self) -> Result<(), String> {
        self.payer.validate("settlement topology payer")?;
        self.payee.validate("settlement topology payee")?;
        if self.payer.role == self.payee.role && self.payer.party_id == self.payee.party_id {
            return Err("settlement topology payer and payee must not be identical".to_string());
        }
        if let Some(beneficiary) = self.beneficiary.as_ref() {
            beneficiary.validate("settlement topology beneficiary")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimPayoutInstructionArtifact {
    pub schema: String,
    pub payout_instruction_id: String,
    pub issued_at: u64,
    pub adjudication: SignedLiabilityClaimAdjudication,
    pub capital_instruction: SignedCapitalExecutionInstruction,
    pub payout_amount: MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl LiabilityClaimPayoutInstructionArtifact {
    pub fn validate(&self) -> Result<(), String> {
        self.adjudication.body.validate()?;
        if !self
            .capital_instruction
            .verify_signature()
            .map_err(|error| error.to_string())?
        {
            return Err(
                "claim payout instruction capital_instruction signature verification failed"
                    .to_string(),
            );
        }
        validate_positive_money(&self.payout_amount, "payout_amount")?;
        let awarded_amount = liability_claim_adjudication_payable_amount(&self.adjudication.body)?;
        if &self.payout_amount != awarded_amount {
            return Err(
                "claim payout instruction payout_amount must match adjudication awarded_amount"
                    .to_string(),
            );
        }
        let capital_instruction = &self.capital_instruction.body;
        if capital_instruction.action != CapitalExecutionInstructionAction::TransferFunds {
            return Err(
                "claim payout instructions require capital_instruction action transfer_funds"
                    .to_string(),
            );
        }
        if capital_instruction.source_kind != CapitalBookSourceKind::FacilityCommitment {
            return Err(
                "claim payout instructions require capital_instruction source_kind facility_commitment"
                    .to_string(),
            );
        }
        let intended_amount = capital_instruction.amount.as_ref().ok_or_else(|| {
            "claim payout instructions require capital_instruction amount".to_string()
        })?;
        if intended_amount != &self.payout_amount {
            return Err(
                "claim payout instruction capital_instruction amount must match payout_amount"
                    .to_string(),
            );
        }
        let subject_key = &self
            .adjudication
            .body
            .dispute
            .body
            .provider_response
            .body
            .claim
            .body
            .bound_coverage
            .body
            .placement
            .body
            .quote_response
            .body
            .quote_request
            .body
            .risk_package
            .body
            .subject_key;
        if &capital_instruction.subject_key != subject_key {
            return Err(
                "claim payout instruction capital_instruction subject_key must match the claim subject"
                    .to_string(),
            );
        }
        if capital_instruction.execution_window.not_after <= self.issued_at {
            return Err(
                "claim payout instructions require a non-stale capital_instruction execution window"
                    .to_string(),
            );
        }
        if capital_instruction.reconciled_state != CapitalExecutionReconciledState::NotObserved
            || capital_instruction.observed_execution.is_some()
        {
            return Err(
                "claim payout instructions require an unreconciled capital_instruction so payout receipts stay explicit"
                    .to_string(),
            );
        }
        Ok(())
    }
}

pub type SignedLiabilityClaimPayoutInstruction =
    SignedExportEnvelope<LiabilityClaimPayoutInstructionArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimPayoutReceiptArtifact {
    pub schema: String,
    pub payout_receipt_id: String,
    pub issued_at: u64,
    pub payout_instruction: SignedLiabilityClaimPayoutInstruction,
    pub payout_receipt_ref: String,
    pub reconciliation_state: LiabilityClaimPayoutReconciliationState,
    pub observed_execution: crate::credit::CapitalExecutionObservation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl LiabilityClaimPayoutReceiptArtifact {
    pub fn validate(&self) -> Result<(), String> {
        self.payout_instruction.body.validate()?;
        if self.payout_receipt_ref.trim().is_empty() {
            return Err("claim payout receipts require a non-empty payout_receipt_ref".to_string());
        }
        if self
            .observed_execution
            .external_reference_id
            .trim()
            .is_empty()
        {
            return Err(
                "claim payout receipts require a non-empty observed_execution external_reference_id"
                    .to_string(),
            );
        }
        validate_positive_money(
            &self.observed_execution.amount,
            "claim payout receipt observed_execution amount",
        )?;
        if self.observed_execution.amount.currency
            != self.payout_instruction.body.payout_amount.currency
        {
            return Err(
                "claim payout receipt observed_execution amount currency must match payout_amount"
                    .to_string(),
            );
        }
        let execution_window = &self
            .payout_instruction
            .body
            .capital_instruction
            .body
            .execution_window;
        if self.observed_execution.observed_at < execution_window.not_before
            || self.observed_execution.observed_at > execution_window.not_after
        {
            return Err(
                "claim payout receipt observed_execution timestamp falls outside the payout instruction execution window"
                    .to_string(),
            );
        }
        match self.reconciliation_state {
            LiabilityClaimPayoutReconciliationState::Matched => {
                if self.observed_execution.amount != self.payout_instruction.body.payout_amount {
                    return Err(
                        "matched claim payout receipts require observed_execution amount to match payout_amount"
                            .to_string(),
                    );
                }
            }
            LiabilityClaimPayoutReconciliationState::AmountMismatch => {
                if self.observed_execution.amount == self.payout_instruction.body.payout_amount {
                    return Err(
                        "amount_mismatch claim payout receipts require observed_execution amount to differ from payout_amount"
                            .to_string(),
                    );
                }
            }
        }
        Ok(())
    }
}

pub type SignedLiabilityClaimPayoutReceipt =
    SignedExportEnvelope<LiabilityClaimPayoutReceiptArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimSettlementInstructionArtifact {
    pub schema: String,
    pub settlement_instruction_id: String,
    pub issued_at: u64,
    pub payout_receipt: SignedLiabilityClaimPayoutReceipt,
    pub capital_book: SignedCapitalBookReport,
    pub settlement_kind: LiabilityClaimSettlementKind,
    pub settlement_amount: MonetaryAmount,
    pub topology: LiabilityClaimSettlementRoleTopology,
    pub authority_chain: Vec<CapitalExecutionAuthorityStep>,
    pub execution_window: CapitalExecutionWindow,
    pub rail: CapitalExecutionRail,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl LiabilityClaimSettlementInstructionArtifact {
    pub fn validate(&self) -> Result<(), String> {
        self.payout_receipt.body.validate()?;
        if !self
            .capital_book
            .verify_signature()
            .map_err(|error| error.to_string())?
        {
            return Err(
                "claim settlement instruction capital_book signature verification failed"
                    .to_string(),
            );
        }
        validate_positive_money(&self.settlement_amount, "settlement_amount")?;
        self.topology.validate()?;
        if self.payout_receipt.body.reconciliation_state
            != LiabilityClaimPayoutReconciliationState::Matched
        {
            return Err(
                "claim settlement instructions require a matched payout_receipt".to_string(),
            );
        }
        if self.settlement_amount.currency
            != self
                .payout_receipt
                .body
                .payout_instruction
                .body
                .payout_amount
                .currency
        {
            return Err(
                "claim settlement instruction settlement_amount currency must match payout_amount"
                    .to_string(),
            );
        }
        if self.settlement_amount.units
            > self
                .payout_receipt
                .body
                .payout_instruction
                .body
                .payout_amount
                .units
        {
            return Err(
                "claim settlement instruction settlement_amount cannot exceed payout_amount"
                    .to_string(),
            );
        }
        let subject_key = &self
            .payout_receipt
            .body
            .payout_instruction
            .body
            .adjudication
            .body
            .dispute
            .body
            .provider_response
            .body
            .claim
            .body
            .bound_coverage
            .body
            .placement
            .body
            .quote_response
            .body
            .quote_request
            .body
            .risk_package
            .body
            .subject_key;
        if self.capital_book.body.subject_key != *subject_key {
            return Err(
                "claim settlement instruction capital_book subject_key must match the claim subject"
                    .to_string(),
            );
        }
        if self.capital_book.body.summary.mixed_currency_book {
            return Err(
                "claim settlement instructions require a capital_book without mixed-currency ambiguity"
                    .to_string(),
            );
        }
        if self.authority_chain.is_empty() {
            return Err(
                "claim settlement instructions require at least one authority_chain step"
                    .to_string(),
            );
        }
        if self.rail.rail_id.trim().is_empty() {
            return Err("claim settlement instructions require rail.rail_id".to_string());
        }
        if self.rail.custody_provider_id.trim().is_empty() {
            return Err(
                "claim settlement instructions require rail.custody_provider_id".to_string(),
            );
        }
        if self.execution_window.not_before > self.execution_window.not_after {
            return Err(
                "claim settlement instructions require execution_window.not_before <= not_after"
                    .to_string(),
            );
        }
        if self.execution_window.not_after <= self.issued_at {
            return Err(
                "claim settlement instructions require a non-stale execution_window".to_string(),
            );
        }
        let mut payer_role_present = false;
        let mut custodian_present = false;
        for step in &self.authority_chain {
            if step.principal_id.trim().is_empty() {
                return Err(
                    "claim settlement authority_chain principal_id cannot be empty".to_string(),
                );
            }
            if step.approved_at > step.expires_at {
                return Err(
                    "claim settlement authority_chain requires approved_at <= expires_at"
                        .to_string(),
                );
            }
            if step.expires_at < self.issued_at {
                return Err(format!(
                    "claim settlement authority step `{}` is stale at issuance time",
                    step.principal_id
                ));
            }
            if step.expires_at < self.execution_window.not_after {
                return Err(format!(
                    "claim settlement authority step `{}` expires before the execution window closes",
                    step.principal_id
                ));
            }
            if step.role == self.topology.payer.role {
                payer_role_present = true;
            }
            if step.role == CapitalExecutionRole::Custodian
                && step.principal_id == self.rail.custody_provider_id
            {
                custodian_present = true;
            }
        }
        if !payer_role_present {
            return Err(
                "claim settlement authority_chain is missing payer-role approval".to_string(),
            );
        }
        if !custodian_present {
            return Err(
                "claim settlement authority_chain is missing the custody-provider execution step"
                    .to_string(),
            );
        }
        Ok(())
    }
}

pub type SignedLiabilityClaimSettlementInstruction =
    SignedExportEnvelope<LiabilityClaimSettlementInstructionArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimSettlementReceiptArtifact {
    pub schema: String,
    pub settlement_receipt_id: String,
    pub issued_at: u64,
    pub settlement_instruction: SignedLiabilityClaimSettlementInstruction,
    pub settlement_receipt_ref: String,
    pub reconciliation_state: LiabilityClaimSettlementReconciliationState,
    pub observed_execution: CapitalExecutionObservation,
    pub observed_payer_id: String,
    pub observed_payee_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl LiabilityClaimSettlementReceiptArtifact {
    pub fn validate(&self) -> Result<(), String> {
        self.settlement_instruction.body.validate()?;
        if self.settlement_receipt_ref.trim().is_empty() {
            return Err(
                "claim settlement receipts require a non-empty settlement_receipt_ref".to_string(),
            );
        }
        if self.observed_payer_id.trim().is_empty() {
            return Err(
                "claim settlement receipts require a non-empty observed_payer_id".to_string(),
            );
        }
        if self.observed_payee_id.trim().is_empty() {
            return Err(
                "claim settlement receipts require a non-empty observed_payee_id".to_string(),
            );
        }
        if self
            .observed_execution
            .external_reference_id
            .trim()
            .is_empty()
        {
            return Err(
                "claim settlement receipts require a non-empty observed_execution external_reference_id"
                    .to_string(),
            );
        }
        validate_positive_money(
            &self.observed_execution.amount,
            "claim settlement receipt observed_execution amount",
        )?;
        if self.observed_execution.amount.currency
            != self.settlement_instruction.body.settlement_amount.currency
        {
            return Err(
                "claim settlement receipt observed_execution amount currency must match settlement_amount"
                    .to_string(),
            );
        }
        let execution_window = &self.settlement_instruction.body.execution_window;
        if self.observed_execution.observed_at < execution_window.not_before
            || self.observed_execution.observed_at > execution_window.not_after
        {
            return Err(
                "claim settlement receipt observed_execution timestamp falls outside the settlement execution window"
                    .to_string(),
            );
        }
        let expected_payer = &self.settlement_instruction.body.topology.payer.party_id;
        let expected_payee = &self.settlement_instruction.body.topology.payee.party_id;
        match self.reconciliation_state {
            LiabilityClaimSettlementReconciliationState::Matched => {
                if self.observed_execution.amount
                    != self.settlement_instruction.body.settlement_amount
                {
                    return Err(
                        "matched claim settlement receipts require observed_execution amount to match settlement_amount"
                            .to_string(),
                    );
                }
                if &self.observed_payer_id != expected_payer
                    || &self.observed_payee_id != expected_payee
                {
                    return Err(
                        "matched claim settlement receipts require observed payer/payee to match the settlement topology"
                            .to_string(),
                    );
                }
            }
            LiabilityClaimSettlementReconciliationState::AmountMismatch => {
                if self.observed_execution.amount
                    == self.settlement_instruction.body.settlement_amount
                {
                    return Err(
                        "amount_mismatch claim settlement receipts require observed_execution amount to differ from settlement_amount"
                            .to_string(),
                    );
                }
                if &self.observed_payer_id != expected_payer
                    || &self.observed_payee_id != expected_payee
                {
                    return Err(
                        "amount_mismatch claim settlement receipts still require observed payer/payee to match the settlement topology"
                            .to_string(),
                    );
                }
            }
            LiabilityClaimSettlementReconciliationState::CounterpartyMismatch => {
                if &self.observed_payer_id == expected_payer
                    && &self.observed_payee_id == expected_payee
                {
                    return Err(
                        "counterparty_mismatch claim settlement receipts require at least one observed counterparty to differ from the settlement topology"
                            .to_string(),
                    );
                }
            }
        }
        Ok(())
    }
}

pub type SignedLiabilityClaimSettlementReceipt =
    SignedExportEnvelope<LiabilityClaimSettlementReceiptArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimWorkflowQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_number: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl Default for LiabilityClaimWorkflowQuery {
    fn default() -> Self {
        Self {
            claim_id: None,
            provider_id: None,
            agent_subject: None,
            jurisdiction: None,
            policy_number: None,
            limit: Some(50),
        }
    }
}

impl LiabilityClaimWorkflowQuery {
    #[must_use]
    pub fn limit_or_default(&self) -> usize {
        self.limit
            .unwrap_or(50)
            .clamp(1, MAX_LIABILITY_CLAIM_WORKFLOW_LIMIT)
    }

    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.limit = Some(self.limit_or_default());
        normalized.claim_id = self.claim_id.as_ref().map(|value| value.trim().to_string());
        normalized.provider_id = self
            .provider_id
            .as_ref()
            .map(|value| value.trim().to_string());
        normalized.agent_subject = self
            .agent_subject
            .as_ref()
            .map(|value| value.trim().to_string());
        normalized.jurisdiction = self
            .jurisdiction
            .as_ref()
            .map(|value| value.trim().to_ascii_lowercase());
        normalized.policy_number = self
            .policy_number
            .as_ref()
            .map(|value| value.trim().to_string());
        normalized
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimWorkflowRow {
    pub claim: SignedLiabilityClaimPackage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_response: Option<SignedLiabilityClaimResponse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispute: Option<SignedLiabilityClaimDispute>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adjudication: Option<SignedLiabilityClaimAdjudication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payout_instruction: Option<SignedLiabilityClaimPayoutInstruction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payout_receipt: Option<SignedLiabilityClaimPayoutReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_instruction: Option<SignedLiabilityClaimSettlementInstruction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_receipt: Option<SignedLiabilityClaimSettlementReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimWorkflowSummary {
    pub matching_claims: u64,
    pub returned_claims: u64,
    pub provider_responses: u64,
    pub accepted_responses: u64,
    pub denied_responses: u64,
    pub disputes: u64,
    pub adjudications: u64,
    pub payout_instructions: u64,
    pub payout_receipts: u64,
    pub matched_payout_receipts: u64,
    pub mismatched_payout_receipts: u64,
    pub settlement_instructions: u64,
    pub settlement_receipts: u64,
    pub matched_settlement_receipts: u64,
    pub mismatched_settlement_receipts: u64,
    pub counterparty_mismatch_settlement_receipts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimWorkflowReport {
    pub schema: String,
    pub generated_at: u64,
    pub query: LiabilityClaimWorkflowQuery,
    pub summary: LiabilityClaimWorkflowSummary,
    pub claims: Vec<LiabilityClaimWorkflowRow>,
}

fn validate_currency_code(value: &str, field_name: &str) -> Result<(), String> {
    let currency = value.trim().to_ascii_uppercase();
    if currency.len() != 3
        || !currency
            .chars()
            .all(|character| character.is_ascii_uppercase())
    {
        return Err(format!(
            "{field_name} must be a three-letter uppercase ISO-style code"
        ));
    }
    Ok(())
}

fn validate_positive_money(amount: &MonetaryAmount, field_name: &str) -> Result<(), String> {
    if amount.units == 0 {
        return Err(format!("{field_name} must be greater than zero"));
    }
    validate_currency_code(&amount.currency, &format!("{field_name} currency"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> LiabilityProviderReport {
        LiabilityProviderReport {
            schema: LIABILITY_PROVIDER_ARTIFACT_SCHEMA.to_string(),
            provider_id: "carrier-alpha".to_string(),
            display_name: "Carrier Alpha".to_string(),
            provider_type: LiabilityProviderType::AdmittedCarrier,
            provider_url: Some("https://carrier.example.com".to_string()),
            lifecycle_state: LiabilityProviderLifecycleState::Active,
            support_boundary: LiabilityProviderSupportBoundary::default(),
            policies: vec![LiabilityJurisdictionPolicy {
                jurisdiction: "us-ny".to_string(),
                coverage_classes: vec![LiabilityCoverageClass::ToolExecution],
                supported_currencies: vec!["USD".to_string()],
                required_evidence: vec![LiabilityEvidenceRequirement::CreditProviderRiskPackage],
                max_coverage_amount: Some(MonetaryAmount {
                    units: 50_000,
                    currency: "USD".to_string(),
                }),
                claims_supported: true,
                quote_ttl_seconds: 3_600,
                notes: None,
            }],
            provenance: LiabilityProviderProvenance {
                configured_by: "operator".to_string(),
                configured_at: 1_700_000_000,
                source_ref: "compliance-runbook".to_string(),
                change_reason: None,
            },
        }
    }

    fn sample_risk_package() -> SignedCreditProviderRiskPackage {
        let keypair = crate::crypto::Keypair::generate();
        let exposure = crate::credit::SignedExposureLedgerReport::sign(
            crate::credit::ExposureLedgerReport {
                schema: crate::credit::EXPOSURE_LEDGER_SCHEMA.to_string(),
                generated_at: 1,
                filters: crate::credit::ExposureLedgerQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..crate::credit::ExposureLedgerQuery::default()
                },
                support_boundary: crate::credit::ExposureLedgerSupportBoundary::default(),
                summary: crate::credit::ExposureLedgerSummary {
                    matching_receipts: 1,
                    returned_receipts: 1,
                    matching_decisions: 0,
                    returned_decisions: 0,
                    active_decisions: 0,
                    superseded_decisions: 0,
                    actionable_receipts: 0,
                    pending_settlement_receipts: 0,
                    failed_settlement_receipts: 0,
                    currencies: vec!["USD".to_string()],
                    mixed_currency_book: false,
                    truncated_receipts: false,
                    truncated_decisions: false,
                },
                positions: vec![crate::credit::ExposureLedgerCurrencyPosition {
                    currency: "USD".to_string(),
                    governed_max_exposure_units: 4_000,
                    reserved_units: 0,
                    settled_units: 4_000,
                    pending_units: 0,
                    failed_units: 0,
                    provisional_loss_units: 0,
                    recovered_units: 0,
                    quoted_premium_units: 0,
                    active_quoted_premium_units: 0,
                }],
                receipts: Vec::new(),
                decisions: Vec::new(),
            },
            &keypair,
        )
        .expect("sign exposure");
        let scorecard = crate::credit::SignedCreditScorecardReport::sign(
            crate::credit::CreditScorecardReport {
                schema: crate::credit::CREDIT_SCORECARD_SCHEMA.to_string(),
                generated_at: 2,
                filters: crate::credit::ExposureLedgerQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..crate::credit::ExposureLedgerQuery::default()
                },
                support_boundary: crate::credit::CreditScorecardSupportBoundary::default(),
                summary: crate::credit::CreditScorecardSummary {
                    matching_receipts: 1,
                    returned_receipts: 1,
                    matching_decisions: 0,
                    returned_decisions: 0,
                    currencies: vec!["USD".to_string()],
                    mixed_currency_book: false,
                    confidence: crate::credit::CreditScorecardConfidence::High,
                    band: crate::credit::CreditScorecardBand::Prime,
                    overall_score: 0.95,
                    anomaly_count: 0,
                    probationary: false,
                },
                reputation: crate::credit::CreditScorecardReputationContext {
                    effective_score: 0.95,
                    probationary: false,
                    resolved_tier: None,
                    imported_signal_count: 0,
                    accepted_imported_signal_count: 0,
                },
                positions: exposure.body.positions.clone(),
                probation: crate::credit::CreditScorecardProbationStatus {
                    probationary: false,
                    reasons: Vec::new(),
                    receipt_count: 1,
                    span_days: 1,
                    target_receipt_count: 1,
                    target_span_days: 1,
                },
                dimensions: Vec::new(),
                anomalies: Vec::new(),
            },
            &keypair,
        )
        .expect("sign scorecard");

        SignedCreditProviderRiskPackage::sign(
            crate::credit::CreditProviderRiskPackage {
                schema: crate::credit::CREDIT_PROVIDER_RISK_PACKAGE_SCHEMA.to_string(),
                generated_at: 3,
                subject_key: "subject-1".to_string(),
                filters: crate::credit::CreditProviderRiskPackageQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..crate::credit::CreditProviderRiskPackageQuery::default()
                },
                support_boundary: crate::credit::CreditProviderRiskPackageSupportBoundary::default(
                ),
                exposure,
                scorecard,
                facility_report: crate::credit::CreditFacilityReport {
                    schema: crate::credit::CREDIT_FACILITY_REPORT_SCHEMA.to_string(),
                    generated_at: 3,
                    filters: crate::credit::ExposureLedgerQuery {
                        agent_subject: Some("subject-1".to_string()),
                        ..crate::credit::ExposureLedgerQuery::default()
                    },
                    scorecard: crate::credit::CreditScorecardSummary {
                        matching_receipts: 1,
                        returned_receipts: 1,
                        matching_decisions: 0,
                        returned_decisions: 0,
                        currencies: vec!["USD".to_string()],
                        mixed_currency_book: false,
                        confidence: crate::credit::CreditScorecardConfidence::High,
                        band: crate::credit::CreditScorecardBand::Prime,
                        overall_score: 0.95,
                        anomaly_count: 0,
                        probationary: false,
                    },
                    disposition: crate::credit::CreditFacilityDisposition::Grant,
                    prerequisites: crate::credit::CreditFacilityPrerequisites {
                        minimum_runtime_assurance_tier:
                            crate::capability::RuntimeAssuranceTier::Verified,
                        runtime_assurance_met: true,
                        certification_required: false,
                        certification_met: true,
                        manual_review_required: false,
                    },
                    support_boundary: crate::credit::CreditFacilitySupportBoundary::default(),
                    terms: Some(crate::credit::CreditFacilityTerms {
                        credit_limit: MonetaryAmount {
                            units: 4_000,
                            currency: "USD".to_string(),
                        },
                        utilization_ceiling_bps: 8_000,
                        reserve_ratio_bps: 1_500,
                        concentration_cap_bps: 3_000,
                        ttl_seconds: 86_400,
                        capital_source:
                            crate::credit::CreditFacilityCapitalSource::OperatorInternal,
                    }),
                    findings: Vec::new(),
                },
                latest_facility: Some(crate::credit::CreditProviderFacilitySnapshot {
                    facility_id: "cfd-1".to_string(),
                    issued_at: 3,
                    expires_at: 4,
                    disposition: crate::credit::CreditFacilityDisposition::Grant,
                    lifecycle_state: crate::credit::CreditFacilityLifecycleState::Active,
                    credit_limit: Some(MonetaryAmount {
                        units: 4_000,
                        currency: "USD".to_string(),
                    }),
                    supersedes_facility_id: None,
                    signer_key: keypair.public_key().to_hex(),
                }),
                runtime_assurance: Some(crate::credit::CreditRuntimeAssuranceState {
                    governed_receipts: 1,
                    runtime_assurance_receipts: 1,
                    highest_tier: Some(crate::capability::RuntimeAssuranceTier::Verified),
                    latest_schema: Some("arc.runtime-attestation.azure-maa.jwt.v1".to_string()),
                    latest_verifier_family: Some(
                        crate::appraisal::AttestationVerifierFamily::AzureMaa,
                    ),
                    latest_verifier: Some("verifier.arc".to_string()),
                    latest_evidence_sha256: Some("sha256-runtime".to_string()),
                    observed_verifier_families: vec![
                        crate::appraisal::AttestationVerifierFamily::AzureMaa,
                    ],
                    stale: false,
                }),
                certification: crate::credit::CreditCertificationState {
                    required: false,
                    state: None,
                    artifact_id: None,
                    checked_at: None,
                    published_at: None,
                },
                recent_loss_history: crate::credit::CreditRecentLossHistory {
                    summary: crate::credit::CreditRecentLossSummary {
                        matching_loss_events: 0,
                        returned_loss_events: 0,
                        failed_settlement_events: 0,
                        provisional_loss_events: 0,
                        recovered_events: 0,
                    },
                    entries: Vec::new(),
                },
                evidence_refs: Vec::new(),
            },
            &keypair,
        )
        .expect("sign risk package")
    }

    #[test]
    fn liability_provider_report_rejects_duplicate_jurisdictions() {
        let mut report = sample_report();
        report.policies.push(report.policies[0].clone());
        let error = report
            .validate()
            .expect_err("duplicate jurisdiction rejected");
        assert!(error.contains("duplicate jurisdiction policy"));
    }

    #[test]
    fn liability_provider_report_rejects_invalid_currency() {
        let mut report = sample_report();
        report.policies[0].supported_currencies = vec!["usdollars".to_string()];
        let error = report.validate().expect_err("invalid currency rejected");
        assert!(error.contains("invalid currency"));
    }

    #[test]
    fn liability_provider_resolution_query_normalizes_fields() {
        let query = LiabilityProviderResolutionQuery {
            provider_id: " carrier-alpha ".to_string(),
            jurisdiction: "US-NY".to_string(),
            coverage_class: LiabilityCoverageClass::ToolExecution,
            currency: "usd".to_string(),
        }
        .normalized();

        assert_eq!(query.provider_id, "carrier-alpha");
        assert_eq!(query.jurisdiction, "us-ny");
        assert_eq!(query.currency, "USD");
    }

    #[test]
    fn liability_quote_request_rejects_currency_mismatch() {
        let report = sample_report();
        let request = LiabilityQuoteRequestArtifact {
            schema: LIABILITY_QUOTE_REQUEST_ARTIFACT_SCHEMA.to_string(),
            quote_request_id: "lqr-test".to_string(),
            issued_at: 1_700_000_000,
            provider_policy: LiabilityProviderPolicyReference {
                provider_id: report.provider_id.clone(),
                provider_record_id: "lpr-test".to_string(),
                display_name: report.display_name.clone(),
                jurisdiction: "us-ny".to_string(),
                coverage_class: LiabilityCoverageClass::ToolExecution,
                currency: "USD".to_string(),
                required_evidence: vec![LiabilityEvidenceRequirement::CreditProviderRiskPackage],
                max_coverage_amount: Some(MonetaryAmount {
                    units: 50_000,
                    currency: "USD".to_string(),
                }),
                claims_supported: true,
                quote_ttl_seconds: 3_600,
                bound_coverage_supported: true,
            },
            requested_coverage_amount: MonetaryAmount {
                units: 10_000,
                currency: "EUR".to_string(),
            },
            requested_effective_from: 1_700_010_000,
            requested_effective_until: 1_700_020_000,
            risk_package: sample_risk_package(),
            notes: None,
        };

        let error = request.validate().expect_err("currency mismatch rejected");
        assert!(error.contains("currency must match provider policy currency"));
    }

    #[test]
    fn liability_market_workflow_query_normalizes_fields() {
        let query = LiabilityMarketWorkflowQuery {
            quote_request_id: Some(" q-1 ".to_string()),
            provider_id: Some(" carrier-alpha ".to_string()),
            agent_subject: Some(" subject-1 ".to_string()),
            jurisdiction: Some("US-NY".to_string()),
            coverage_class: Some(LiabilityCoverageClass::ToolExecution),
            currency: Some("usd".to_string()),
            limit: Some(500),
        }
        .normalized();

        assert_eq!(query.quote_request_id.as_deref(), Some("q-1"));
        assert_eq!(query.provider_id.as_deref(), Some("carrier-alpha"));
        assert_eq!(query.agent_subject.as_deref(), Some("subject-1"));
        assert_eq!(query.jurisdiction.as_deref(), Some("us-ny"));
        assert_eq!(query.currency.as_deref(), Some("USD"));
        assert_eq!(query.limit, Some(MAX_LIABILITY_MARKET_WORKFLOW_LIMIT));
    }
}
