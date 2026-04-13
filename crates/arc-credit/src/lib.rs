pub use arc_appraisal as appraisal;
pub use arc_core_types::{capability, crypto, receipt};
pub use arc_underwriting as underwriting;

use serde::{Deserialize, Serialize};

use crate::appraisal::AttestationVerifierFamily;
use crate::capability::{GovernedAutonomyTier, MonetaryAmount, RuntimeAssuranceTier};
use crate::receipt::{Decision, SettlementStatus, SignedExportEnvelope};
use crate::underwriting::{
    UnderwritingCertificationState, UnderwritingDecisionLifecycleState,
    UnderwritingDecisionOutcome, UnderwritingReviewState, UnderwritingRiskClass,
};

pub const EXPOSURE_LEDGER_SCHEMA: &str = "arc.credit.exposure-ledger.v1";
pub const CREDIT_SCORECARD_SCHEMA: &str = "arc.credit.scorecard.v1";
pub const CREDIT_FACILITY_REPORT_SCHEMA: &str = "arc.credit.facility-report.v1";
pub const CREDIT_FACILITY_ARTIFACT_SCHEMA: &str = "arc.credit.facility.v1";
pub const CREDIT_FACILITY_LIST_REPORT_SCHEMA: &str = "arc.credit.facility-list.v1";
pub const CREDIT_BOND_REPORT_SCHEMA: &str = "arc.credit.bond-report.v1";
pub const CREDIT_BOND_ARTIFACT_SCHEMA: &str = "arc.credit.bond.v1";
pub const CREDIT_BOND_LIST_REPORT_SCHEMA: &str = "arc.credit.bond-list.v1";
pub const CREDIT_LOSS_LIFECYCLE_REPORT_SCHEMA: &str = "arc.credit.loss-lifecycle-report.v1";
pub const CREDIT_LOSS_LIFECYCLE_ARTIFACT_SCHEMA: &str = "arc.credit.loss-lifecycle.v1";
pub const CREDIT_LOSS_LIFECYCLE_LIST_REPORT_SCHEMA: &str = "arc.credit.loss-lifecycle-list.v1";
pub const CREDIT_BACKTEST_REPORT_SCHEMA: &str = "arc.credit.backtest-report.v1";
pub const CREDIT_PROVIDER_RISK_PACKAGE_SCHEMA: &str = "arc.credit.provider-risk-package.v1";
pub const CAPITAL_BOOK_REPORT_SCHEMA: &str = "arc.credit.capital-book.v1";
pub const CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA: &str = "arc.credit.capital-instruction.v1";
pub const CAPITAL_ALLOCATION_DECISION_ARTIFACT_SCHEMA: &str = "arc.credit.capital-allocation.v1";
pub const CREDIT_BONDED_EXECUTION_SIMULATION_REPORT_SCHEMA: &str =
    "arc.credit.bonded-execution-simulation-report.v1";
pub const MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT: usize = 200;
pub const MAX_EXPOSURE_LEDGER_DECISION_LIMIT: usize = 200;
pub const MAX_CREDIT_FACILITY_LIST_LIMIT: usize = 100;
pub const MAX_CREDIT_BOND_LIST_LIMIT: usize = 100;
pub const MAX_CREDIT_LOSS_LIFECYCLE_LIST_LIMIT: usize = 100;
pub const MAX_CREDIT_BACKTEST_WINDOW_LIMIT: usize = 24;
pub const MAX_CREDIT_PROVIDER_LOSS_LIMIT: usize = 25;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExposureLedgerQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_limit: Option<usize>,
}

impl Default for ExposureLedgerQuery {
    fn default() -> Self {
        Self {
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            since: None,
            until: None,
            receipt_limit: Some(100),
            decision_limit: Some(50),
        }
    }
}

impl ExposureLedgerQuery {
    #[must_use]
    pub fn receipt_limit_or_default(&self) -> usize {
        self.receipt_limit
            .unwrap_or(100)
            .clamp(1, MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT)
    }

    #[must_use]
    pub fn decision_limit_or_default(&self) -> usize {
        self.decision_limit
            .unwrap_or(50)
            .clamp(1, MAX_EXPOSURE_LEDGER_DECISION_LIMIT)
    }

    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.receipt_limit = Some(self.receipt_limit_or_default());
        normalized.decision_limit = Some(self.decision_limit_or_default());
        normalized
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.capability_id.is_none()
            && self.agent_subject.is_none()
            && self.tool_server.is_none()
        {
            return Err(
                "exposure ledger queries require at least one anchor: --capability, --agent-subject, or --tool-server".to_string(),
            );
        }
        if self.tool_name.is_some() && self.tool_server.is_none() {
            return Err(
                "exposure ledger queries that specify --tool-name must also specify --tool-server"
                    .to_string(),
            );
        }
        if let (Some(since), Some(until)) = (self.since, self.until) {
            if since > until {
                return Err(
                    "exposure ledger queries require --since to be less than or equal to --until"
                        .to_string(),
                );
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExposureLedgerEvidenceKind {
    Receipt,
    SettlementReconciliation,
    MeteredBillingReconciliation,
    UnderwritingDecision,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExposureLedgerEvidenceReference {
    pub kind: ExposureLedgerEvidenceKind,
    pub reference_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExposureLedgerSupportBoundary {
    pub governed_receipts_authoritative: bool,
    pub underwriting_decisions_authoritative: bool,
    pub settlement_reconciliation_authoritative: bool,
    pub cross_currency_netting_supported: bool,
    pub claim_adjudication_supported: bool,
    pub recovery_lifecycle_supported: bool,
}

impl Default for ExposureLedgerSupportBoundary {
    fn default() -> Self {
        Self {
            governed_receipts_authoritative: true,
            underwriting_decisions_authoritative: true,
            settlement_reconciliation_authoritative: true,
            cross_currency_netting_supported: false,
            claim_adjudication_supported: false,
            recovery_lifecycle_supported: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExposureLedgerCurrencyPosition {
    pub currency: String,
    pub governed_max_exposure_units: u64,
    pub reserved_units: u64,
    pub settled_units: u64,
    pub pending_units: u64,
    pub failed_units: u64,
    pub provisional_loss_units: u64,
    pub recovered_units: u64,
    pub quoted_premium_units: u64,
    pub active_quoted_premium_units: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExposureLedgerReceiptEntry {
    pub receipt_id: String,
    pub timestamp: u64,
    pub capability_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_key: Option<String>,
    pub tool_server: String,
    pub tool_name: String,
    pub decision: Decision,
    pub settlement_status: SettlementStatus,
    pub action_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed_max_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub financial_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserve_required_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provisional_loss_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovered_amount: Option<MonetaryAmount>,
    pub metered_action_required: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<ExposureLedgerEvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExposureLedgerDecisionEntry {
    pub decision_id: String,
    pub issued_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    pub outcome: UnderwritingDecisionOutcome,
    pub lifecycle_state: UnderwritingDecisionLifecycleState,
    pub review_state: UnderwritingReviewState,
    pub risk_class: UnderwritingRiskClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_decision_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quoted_premium_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<ExposureLedgerEvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExposureLedgerSummary {
    pub matching_receipts: u64,
    pub returned_receipts: u64,
    pub matching_decisions: u64,
    pub returned_decisions: u64,
    pub active_decisions: u64,
    pub superseded_decisions: u64,
    pub actionable_receipts: u64,
    pub pending_settlement_receipts: u64,
    pub failed_settlement_receipts: u64,
    pub currencies: Vec<String>,
    pub mixed_currency_book: bool,
    pub truncated_receipts: bool,
    pub truncated_decisions: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExposureLedgerReport {
    pub schema: String,
    pub generated_at: u64,
    pub filters: ExposureLedgerQuery,
    pub support_boundary: ExposureLedgerSupportBoundary,
    pub summary: ExposureLedgerSummary,
    pub positions: Vec<ExposureLedgerCurrencyPosition>,
    pub receipts: Vec<ExposureLedgerReceiptEntry>,
    pub decisions: Vec<ExposureLedgerDecisionEntry>,
}

pub type SignedExposureLedgerReport = SignedExportEnvelope<ExposureLedgerReport>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditScorecardConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditScorecardBand {
    Prime,
    Standard,
    Guarded,
    Probationary,
    Restricted,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditScorecardDimensionKind {
    ReputationSupport,
    SettlementDiscipline,
    LossPressure,
    ExposureStewardship,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditScorecardReasonCode {
    SparseReceiptHistory,
    SparseDayHistory,
    LowConfidence,
    PendingSettlementBacklog,
    FailedSettlementBacklog,
    ProvisionalLossPressure,
    MixedCurrencyBook,
    LowReputation,
    ImportedTrustDependency,
    MissingDecisionCoverage,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditScorecardAnomalySeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditScorecardEvidenceKind {
    Receipt,
    SettlementReconciliation,
    UnderwritingDecision,
    ReputationInspection,
    ExposureLedger,
    CreditBond,
    CreditLossLifecycle,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditScorecardEvidenceReference {
    pub kind: CreditScorecardEvidenceKind,
    pub reference_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditScorecardSupportBoundary {
    pub subject_scoped_only: bool,
    pub cross_currency_netting_supported: bool,
    pub capital_allocation_supported: bool,
    pub facility_policy_supported: bool,
}

impl Default for CreditScorecardSupportBoundary {
    fn default() -> Self {
        Self {
            subject_scoped_only: true,
            cross_currency_netting_supported: false,
            capital_allocation_supported: false,
            facility_policy_supported: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditScorecardDimension {
    pub kind: CreditScorecardDimensionKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    pub weight: f64,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<CreditScorecardEvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditScorecardProbationStatus {
    pub probationary: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<CreditScorecardReasonCode>,
    pub receipt_count: u64,
    pub span_days: u64,
    pub target_receipt_count: u64,
    pub target_span_days: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditScorecardAnomaly {
    pub code: CreditScorecardReasonCode,
    pub severity: CreditScorecardAnomalySeverity,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<CreditScorecardEvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditScorecardReputationContext {
    pub effective_score: f64,
    pub probationary: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_tier: Option<String>,
    pub imported_signal_count: usize,
    pub accepted_imported_signal_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditScorecardSummary {
    pub matching_receipts: u64,
    pub returned_receipts: u64,
    pub matching_decisions: u64,
    pub returned_decisions: u64,
    pub currencies: Vec<String>,
    pub mixed_currency_book: bool,
    pub confidence: CreditScorecardConfidence,
    pub band: CreditScorecardBand,
    pub overall_score: f64,
    pub anomaly_count: u64,
    pub probationary: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditScorecardReport {
    pub schema: String,
    pub generated_at: u64,
    pub filters: ExposureLedgerQuery,
    pub support_boundary: CreditScorecardSupportBoundary,
    pub summary: CreditScorecardSummary,
    pub reputation: CreditScorecardReputationContext,
    pub positions: Vec<ExposureLedgerCurrencyPosition>,
    pub probation: CreditScorecardProbationStatus,
    pub dimensions: Vec<CreditScorecardDimension>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anomalies: Vec<CreditScorecardAnomaly>,
}

pub type SignedCreditScorecardReport = SignedExportEnvelope<CreditScorecardReport>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditFacilityDisposition {
    Grant,
    ManualReview,
    Deny,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditFacilityLifecycleState {
    Active,
    Superseded,
    Denied,
    Expired,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditFacilityCapitalSource {
    OperatorInternal,
    ManualProviderReview,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditFacilityReasonCode {
    ScoreRestricted,
    ProbationaryScore,
    LowConfidence,
    MixedCurrencyBook,
    MixedRuntimeAssuranceProvenance,
    MissingRuntimeAssurance,
    CertificationNotActive,
    FailedSettlementBacklog,
    PendingSettlementBacklog,
    FacilityGranted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditFacilityTerms {
    pub credit_limit: MonetaryAmount,
    pub utilization_ceiling_bps: u16,
    pub reserve_ratio_bps: u16,
    pub concentration_cap_bps: u16,
    pub ttl_seconds: u64,
    pub capital_source: CreditFacilityCapitalSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditFacilityPrerequisites {
    pub minimum_runtime_assurance_tier: RuntimeAssuranceTier,
    pub runtime_assurance_met: bool,
    pub certification_required: bool,
    pub certification_met: bool,
    pub manual_review_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditFacilityFinding {
    pub code: CreditFacilityReasonCode,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<CreditScorecardEvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditFacilitySupportBoundary {
    pub provider_neutral_policy: bool,
    pub cross_currency_allocation_supported: bool,
    pub bond_execution_supported: bool,
}

impl Default for CreditFacilitySupportBoundary {
    fn default() -> Self {
        Self {
            provider_neutral_policy: true,
            cross_currency_allocation_supported: false,
            bond_execution_supported: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditFacilityReport {
    pub schema: String,
    pub generated_at: u64,
    pub filters: ExposureLedgerQuery,
    pub scorecard: CreditScorecardSummary,
    pub disposition: CreditFacilityDisposition,
    pub prerequisites: CreditFacilityPrerequisites,
    pub support_boundary: CreditFacilitySupportBoundary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms: Option<CreditFacilityTerms>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<CreditFacilityFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditFacilityArtifact {
    pub schema: String,
    pub facility_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub lifecycle_state: CreditFacilityLifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_facility_id: Option<String>,
    pub report: CreditFacilityReport,
}

pub type SignedCreditFacility = SignedExportEnvelope<CreditFacilityArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditFacilityListQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facility_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disposition: Option<CreditFacilityDisposition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_state: Option<CreditFacilityLifecycleState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl Default for CreditFacilityListQuery {
    fn default() -> Self {
        Self {
            facility_id: None,
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            disposition: None,
            lifecycle_state: None,
            limit: Some(50),
        }
    }
}

impl CreditFacilityListQuery {
    #[must_use]
    pub fn limit_or_default(&self) -> usize {
        self.limit
            .unwrap_or(50)
            .clamp(1, MAX_CREDIT_FACILITY_LIST_LIMIT)
    }

    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.limit = Some(self.limit_or_default());
        normalized
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditFacilityRow {
    pub facility: SignedCreditFacility,
    pub lifecycle_state: CreditFacilityLifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by_facility_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditFacilityListSummary {
    pub matching_facilities: u64,
    pub returned_facilities: u64,
    pub active_facilities: u64,
    pub superseded_facilities: u64,
    pub denied_facilities: u64,
    pub expired_facilities: u64,
    pub granted_facilities: u64,
    pub manual_review_facilities: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditFacilityListReport {
    pub schema: String,
    pub generated_at: u64,
    pub query: CreditFacilityListQuery,
    pub summary: CreditFacilityListSummary,
    pub facilities: Vec<CreditFacilityRow>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditBondDisposition {
    Lock,
    Hold,
    Release,
    Impair,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditBondLifecycleState {
    Active,
    Superseded,
    Released,
    Impaired,
    Expired,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditBondReasonCode {
    ActiveFacilityMissing,
    MixedCurrencyBook,
    PendingSettlementBacklog,
    FailedSettlementBacklog,
    ProvisionalLossOutstanding,
    ReserveLocked,
    ReserveHeld,
    ReserveReleased,
    UnderCollateralized,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondTerms {
    pub facility_id: String,
    pub credit_limit: MonetaryAmount,
    pub collateral_amount: MonetaryAmount,
    pub reserve_requirement_amount: MonetaryAmount,
    pub outstanding_exposure_amount: MonetaryAmount,
    pub reserve_ratio_bps: u16,
    pub coverage_ratio_bps: u16,
    pub capital_source: CreditFacilityCapitalSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondPrerequisites {
    pub active_facility_required: bool,
    pub active_facility_met: bool,
    pub runtime_assurance_met: bool,
    pub certification_required: bool,
    pub certification_met: bool,
    pub currency_coherent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondFinding {
    pub code: CreditBondReasonCode,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<CreditScorecardEvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondSupportBoundary {
    pub reserve_accounting_authoritative: bool,
    pub external_escrow_execution_supported: bool,
    pub autonomy_gating_supported: bool,
}

impl Default for CreditBondSupportBoundary {
    fn default() -> Self {
        Self {
            reserve_accounting_authoritative: true,
            external_escrow_execution_supported: false,
            autonomy_gating_supported: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondReport {
    pub schema: String,
    pub generated_at: u64,
    pub filters: ExposureLedgerQuery,
    pub exposure: ExposureLedgerSummary,
    pub scorecard: CreditScorecardSummary,
    pub disposition: CreditBondDisposition,
    pub prerequisites: CreditBondPrerequisites,
    pub support_boundary: CreditBondSupportBoundary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_facility_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms: Option<CreditBondTerms>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<CreditBondFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondArtifact {
    pub schema: String,
    pub bond_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub lifecycle_state: CreditBondLifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_bond_id: Option<String>,
    pub report: CreditBondReport,
}

pub type SignedCreditBond = SignedExportEnvelope<CreditBondArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondListQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facility_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disposition: Option<CreditBondDisposition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_state: Option<CreditBondLifecycleState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl Default for CreditBondListQuery {
    fn default() -> Self {
        Self {
            bond_id: None,
            facility_id: None,
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            disposition: None,
            lifecycle_state: None,
            limit: Some(50),
        }
    }
}

impl CreditBondListQuery {
    #[must_use]
    pub fn limit_or_default(&self) -> usize {
        self.limit
            .unwrap_or(50)
            .clamp(1, MAX_CREDIT_BOND_LIST_LIMIT)
    }

    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.limit = Some(self.limit_or_default());
        normalized
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondRow {
    pub bond: SignedCreditBond,
    pub lifecycle_state: CreditBondLifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by_bond_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondListSummary {
    pub matching_bonds: u64,
    pub returned_bonds: u64,
    pub active_bonds: u64,
    pub superseded_bonds: u64,
    pub released_bonds: u64,
    pub impaired_bonds: u64,
    pub expired_bonds: u64,
    pub locked_bonds: u64,
    pub held_bonds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondListReport {
    pub schema: String,
    pub generated_at: u64,
    pub query: CreditBondListQuery,
    pub summary: CreditBondListSummary,
    pub bonds: Vec<CreditBondRow>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditLossLifecycleEventKind {
    Delinquency,
    Recovery,
    ReserveRelease,
    ReserveSlash,
    WriteOff,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditLossLifecycleReasonCode {
    ActiveBondRequired,
    BondNotActive,
    DelinquencyEvidenceMissing,
    OutstandingDelinquencyRequired,
    AmountRequired,
    AmountCurrencyMismatch,
    AmountExceedsOutstandingDelinquency,
    OutstandingExposureBlocksReserveRelease,
    ReserveAlreadyReleased,
    DelinquencyRecorded,
    RecoveryRecorded,
    ReserveReleased,
    ReserveSlashed,
    WriteOffRecorded,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditReserveControlExecutionState {
    PendingExecution,
    Executed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditReserveControlAppealState {
    Unsupported,
    Open,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditLossLifecycleQuery {
    pub bond_id: String,
    pub event_kind: CreditLossLifecycleEventKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<MonetaryAmount>,
}

impl CreditLossLifecycleQuery {
    pub fn validate(&self) -> Result<(), String> {
        if self.bond_id.trim().is_empty() {
            return Err("credit loss lifecycle requests require --bond-id".to_string());
        }
        if self.amount.as_ref().is_some_and(|amount| amount.units == 0) {
            return Err("credit loss lifecycle amounts must be greater than zero".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditLossLifecycleSummary {
    pub bond_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facility_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    pub current_bond_lifecycle_state: CreditBondLifecycleState,
    pub projected_bond_lifecycle_state: CreditBondLifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_delinquent_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_recovered_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_written_off_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_released_reserve_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_slashed_reserve_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outstanding_delinquent_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub releaseable_reserve_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserve_control_source_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_state: Option<CreditReserveControlExecutionState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appeal_state: Option<CreditReserveControlAppealState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appeal_window_ends_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_amount: Option<MonetaryAmount>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditLossLifecycleFinding {
    pub code: CreditLossLifecycleReasonCode,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<CreditScorecardEvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditLossLifecycleSupportBoundary {
    pub immutable_lifecycle_authoritative: bool,
    pub bond_lifecycle_projection_authoritative: bool,
    pub external_claim_adjudication_supported: bool,
    pub automatic_capital_execution_supported: bool,
    pub reserve_control_execution_supported: bool,
    pub appeal_window_supported: bool,
}

impl Default for CreditLossLifecycleSupportBoundary {
    fn default() -> Self {
        Self {
            immutable_lifecycle_authoritative: true,
            bond_lifecycle_projection_authoritative: true,
            external_claim_adjudication_supported: false,
            automatic_capital_execution_supported: false,
            reserve_control_execution_supported: true,
            appeal_window_supported: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditLossLifecycleReport {
    pub schema: String,
    pub generated_at: u64,
    pub query: CreditLossLifecycleQuery,
    pub summary: CreditLossLifecycleSummary,
    pub support_boundary: CreditLossLifecycleSupportBoundary,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<CreditLossLifecycleFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditLossLifecycleArtifact {
    pub schema: String,
    pub event_id: String,
    pub issued_at: u64,
    pub bond_id: String,
    pub event_kind: CreditLossLifecycleEventKind,
    pub projected_bond_lifecycle_state: CreditBondLifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserve_control_source_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authority_chain: Vec<CapitalExecutionAuthorityStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_window: Option<CapitalExecutionWindow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rail: Option<CapitalExecutionRail>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_execution: Option<CapitalExecutionObservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconciled_state: Option<CapitalExecutionReconciledState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_state: Option<CreditReserveControlExecutionState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appeal_state: Option<CreditReserveControlAppealState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appeal_window_ends_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub report: CreditLossLifecycleReport,
}

pub type SignedCreditLossLifecycle = SignedExportEnvelope<CreditLossLifecycleArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditLossLifecycleListQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facility_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_kind: Option<CreditLossLifecycleEventKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl Default for CreditLossLifecycleListQuery {
    fn default() -> Self {
        Self {
            event_id: None,
            bond_id: None,
            facility_id: None,
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            event_kind: None,
            limit: Some(50),
        }
    }
}

impl CreditLossLifecycleListQuery {
    #[must_use]
    pub fn limit_or_default(&self) -> usize {
        self.limit
            .unwrap_or(50)
            .clamp(1, MAX_CREDIT_LOSS_LIFECYCLE_LIST_LIMIT)
    }

    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.limit = Some(self.limit_or_default());
        normalized
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditLossLifecycleRow {
    pub event: SignedCreditLossLifecycle,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditLossLifecycleListSummary {
    pub matching_events: u64,
    pub returned_events: u64,
    pub delinquency_events: u64,
    pub recovery_events: u64,
    pub reserve_release_events: u64,
    pub reserve_slash_events: u64,
    pub write_off_events: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditLossLifecycleListReport {
    pub schema: String,
    pub generated_at: u64,
    pub query: CreditLossLifecycleListQuery,
    pub summary: CreditLossLifecycleListSummary,
    pub events: Vec<CreditLossLifecycleRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBacktestQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_after_seconds: Option<u64>,
}

impl Default for CreditBacktestQuery {
    fn default() -> Self {
        Self {
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            since: None,
            until: None,
            receipt_limit: Some(100),
            decision_limit: Some(50),
            window_seconds: Some(7 * 86_400),
            window_count: Some(4),
            stale_after_seconds: Some(30 * 86_400),
        }
    }
}

impl CreditBacktestQuery {
    #[must_use]
    pub fn receipt_limit_or_default(&self) -> usize {
        self.receipt_limit
            .unwrap_or(100)
            .clamp(1, MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT)
    }

    #[must_use]
    pub fn decision_limit_or_default(&self) -> usize {
        self.decision_limit
            .unwrap_or(50)
            .clamp(1, MAX_EXPOSURE_LEDGER_DECISION_LIMIT)
    }

    #[must_use]
    pub fn window_seconds_or_default(&self) -> u64 {
        self.window_seconds.unwrap_or(7 * 86_400).max(1)
    }

    #[must_use]
    pub fn window_count_or_default(&self) -> usize {
        self.window_count
            .unwrap_or(4)
            .clamp(1, MAX_CREDIT_BACKTEST_WINDOW_LIMIT)
    }

    #[must_use]
    pub fn stale_after_seconds_or_default(&self) -> u64 {
        self.stale_after_seconds.unwrap_or(30 * 86_400).max(1)
    }

    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.receipt_limit = Some(self.receipt_limit_or_default());
        normalized.decision_limit = Some(self.decision_limit_or_default());
        normalized.window_seconds = Some(self.window_seconds_or_default());
        normalized.window_count = Some(self.window_count_or_default());
        normalized.stale_after_seconds = Some(self.stale_after_seconds_or_default());
        normalized
    }

    #[must_use]
    pub fn exposure_query(&self) -> ExposureLedgerQuery {
        ExposureLedgerQuery {
            capability_id: self.capability_id.clone(),
            agent_subject: self.agent_subject.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            since: self.since,
            until: self.until,
            receipt_limit: self.receipt_limit,
            decision_limit: self.decision_limit,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        self.exposure_query().validate()?;
        if self.agent_subject.is_none() {
            return Err(
                "credit backtests require --agent-subject because scorecards and facilities are subject-scoped"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditBacktestReasonCode {
    ScoreBandShift,
    FacilityDispositionShift,
    MixedCurrencyBook,
    StaleEvidence,
    FacilityOverUtilization,
    PendingSettlementBacklog,
    FailedSettlementBacklog,
    MissingRuntimeAssurance,
    CertificationNotActive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBacktestWindow {
    pub index: u64,
    pub window_started_at: u64,
    pub window_ended_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub newest_receipt_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_band: Option<CreditScorecardBand>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_disposition: Option<CreditFacilityDisposition>,
    pub simulated_scorecard: CreditScorecardSummary,
    pub simulated_disposition: CreditFacilityDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simulated_terms: Option<CreditFacilityTerms>,
    pub stale_evidence: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utilization_bps: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reason_codes: Vec<CreditBacktestReasonCode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBacktestSummary {
    pub windows_evaluated: u64,
    pub drift_windows: u64,
    pub score_band_changes: u64,
    pub facility_disposition_changes: u64,
    pub manual_review_windows: u64,
    pub denied_windows: u64,
    pub stale_evidence_windows: u64,
    pub mixed_currency_windows: u64,
    pub over_utilized_windows: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBacktestReport {
    pub schema: String,
    pub generated_at: u64,
    pub query: CreditBacktestQuery,
    pub summary: CreditBacktestSummary,
    pub windows: Vec<CreditBacktestWindow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditProviderRiskPackageQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recent_loss_limit: Option<usize>,
}

impl Default for CreditProviderRiskPackageQuery {
    fn default() -> Self {
        Self {
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            since: None,
            until: None,
            receipt_limit: Some(100),
            decision_limit: Some(50),
            recent_loss_limit: Some(10),
        }
    }
}

impl CreditProviderRiskPackageQuery {
    #[must_use]
    pub fn recent_loss_limit_or_default(&self) -> usize {
        self.recent_loss_limit
            .unwrap_or(10)
            .clamp(1, MAX_CREDIT_PROVIDER_LOSS_LIMIT)
    }

    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.receipt_limit = Some(
            self.receipt_limit
                .unwrap_or(100)
                .clamp(1, MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT),
        );
        normalized.decision_limit = Some(
            self.decision_limit
                .unwrap_or(50)
                .clamp(1, MAX_EXPOSURE_LEDGER_DECISION_LIMIT),
        );
        normalized.recent_loss_limit = Some(self.recent_loss_limit_or_default());
        normalized
    }

    #[must_use]
    pub fn exposure_query(&self) -> ExposureLedgerQuery {
        ExposureLedgerQuery {
            capability_id: self.capability_id.clone(),
            agent_subject: self.agent_subject.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            since: self.since,
            until: self.until,
            receipt_limit: self.receipt_limit,
            decision_limit: self.decision_limit,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        self.exposure_query().validate()?;
        if self.agent_subject.is_none() {
            return Err(
                "provider risk packages require --agent-subject because the package is subject-scoped"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditRecentLossEntry {
    pub receipt_id: String,
    pub observed_at: u64,
    pub settlement_status: SettlementStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub financial_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provisional_loss_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovered_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<ExposureLedgerEvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditRecentLossSummary {
    pub matching_loss_events: u64,
    pub returned_loss_events: u64,
    pub failed_settlement_events: u64,
    pub provisional_loss_events: u64,
    pub recovered_events: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditRecentLossHistory {
    pub summary: CreditRecentLossSummary,
    pub entries: Vec<CreditRecentLossEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditRuntimeAssuranceState {
    pub governed_receipts: u64,
    pub runtime_assurance_receipts: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highest_tier: Option<RuntimeAssuranceTier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_verifier_family: Option<AttestationVerifierFamily>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_verifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_evidence_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed_verifier_families: Vec<AttestationVerifierFamily>,
    pub stale: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditCertificationState {
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<UnderwritingCertificationState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditProviderRiskPackageSupportBoundary {
    pub signed_exposure_authoritative: bool,
    pub signed_scorecard_authoritative: bool,
    pub facility_policy_authoritative: bool,
    pub external_capital_review_supported: bool,
    pub autonomous_pricing_supported: bool,
    pub liability_market_supported: bool,
}

impl Default for CreditProviderRiskPackageSupportBoundary {
    fn default() -> Self {
        Self {
            signed_exposure_authoritative: true,
            signed_scorecard_authoritative: true,
            facility_policy_authoritative: true,
            external_capital_review_supported: true,
            autonomous_pricing_supported: false,
            liability_market_supported: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditProviderFacilitySnapshot {
    pub facility_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub disposition: CreditFacilityDisposition,
    pub lifecycle_state: CreditFacilityLifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credit_limit: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_facility_id: Option<String>,
    pub signer_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditProviderRiskPackage {
    pub schema: String,
    pub generated_at: u64,
    pub subject_key: String,
    pub filters: CreditProviderRiskPackageQuery,
    pub support_boundary: CreditProviderRiskPackageSupportBoundary,
    pub exposure: SignedExposureLedgerReport,
    pub scorecard: SignedCreditScorecardReport,
    pub facility_report: CreditFacilityReport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_facility: Option<CreditProviderFacilitySnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_assurance: Option<CreditRuntimeAssuranceState>,
    pub certification: CreditCertificationState,
    pub recent_loss_history: CreditRecentLossHistory,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<CreditScorecardEvidenceReference>,
}

pub type SignedCreditProviderRiskPackage = SignedExportEnvelope<CreditProviderRiskPackage>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalBookQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facility_limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond_limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss_event_limit: Option<usize>,
}

impl Default for CapitalBookQuery {
    fn default() -> Self {
        Self {
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            since: None,
            until: None,
            receipt_limit: Some(100),
            facility_limit: Some(10),
            bond_limit: Some(10),
            loss_event_limit: Some(25),
        }
    }
}

impl CapitalBookQuery {
    #[must_use]
    pub fn receipt_limit_or_default(&self) -> usize {
        self.receipt_limit
            .unwrap_or(100)
            .clamp(1, MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT)
    }

    #[must_use]
    pub fn facility_limit_or_default(&self) -> usize {
        self.facility_limit
            .unwrap_or(10)
            .clamp(1, MAX_CREDIT_FACILITY_LIST_LIMIT)
    }

    #[must_use]
    pub fn bond_limit_or_default(&self) -> usize {
        self.bond_limit
            .unwrap_or(10)
            .clamp(1, MAX_CREDIT_BOND_LIST_LIMIT)
    }

    #[must_use]
    pub fn loss_event_limit_or_default(&self) -> usize {
        self.loss_event_limit
            .unwrap_or(25)
            .clamp(1, MAX_CREDIT_LOSS_LIFECYCLE_LIST_LIMIT)
    }

    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.receipt_limit = Some(self.receipt_limit_or_default());
        normalized.facility_limit = Some(self.facility_limit_or_default());
        normalized.bond_limit = Some(self.bond_limit_or_default());
        normalized.loss_event_limit = Some(self.loss_event_limit_or_default());
        normalized
    }

    #[must_use]
    pub fn exposure_query(&self) -> ExposureLedgerQuery {
        ExposureLedgerQuery {
            capability_id: self.capability_id.clone(),
            agent_subject: self.agent_subject.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            since: self.since,
            until: self.until,
            receipt_limit: self.receipt_limit,
            decision_limit: Some(1),
        }
    }

    #[must_use]
    pub fn facility_query(&self) -> CreditFacilityListQuery {
        CreditFacilityListQuery {
            facility_id: None,
            capability_id: self.capability_id.clone(),
            agent_subject: self.agent_subject.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            disposition: None,
            lifecycle_state: None,
            limit: self.facility_limit,
        }
    }

    #[must_use]
    pub fn bond_query(&self) -> CreditBondListQuery {
        CreditBondListQuery {
            bond_id: None,
            facility_id: None,
            capability_id: self.capability_id.clone(),
            agent_subject: self.agent_subject.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            disposition: None,
            lifecycle_state: None,
            limit: self.bond_limit,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        self.exposure_query().validate()?;
        if self.agent_subject.is_none() {
            return Err(
                "capital book queries require --agent-subject because source-of-funds truth must resolve one counterparty"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapitalBookSourceKind {
    FacilityCommitment,
    ReserveBook,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapitalBookRole {
    OperatorTreasury,
    ExternalCapitalProvider,
    AgentCounterparty,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapitalBookEventKind {
    Commit,
    Hold,
    Draw,
    Disburse,
    Release,
    Repay,
    Impair,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapitalBookEvidenceKind {
    CreditFacility,
    CreditBond,
    CreditLossLifecycle,
    Receipt,
    SettlementReconciliation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalBookEvidenceReference {
    pub kind: CapitalBookEvidenceKind,
    pub reference_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalBookSupportBoundary {
    pub source_of_funds_authoritative: bool,
    pub mixed_currency_netting_supported: bool,
    pub custody_execution_supported: bool,
    pub automatic_capital_execution_supported: bool,
}

impl Default for CapitalBookSupportBoundary {
    fn default() -> Self {
        Self {
            source_of_funds_authoritative: true,
            mixed_currency_netting_supported: false,
            custody_execution_supported: false,
            automatic_capital_execution_supported: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalBookSource {
    pub source_id: String,
    pub kind: CapitalBookSourceKind,
    pub owner_role: CapitalBookRole,
    pub counterparty_role: CapitalBookRole,
    pub counterparty_id: String,
    pub currency: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capital_source: Option<CreditFacilityCapitalSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facility_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub committed_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drawn_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disbursed_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repaid_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impaired_amount: Option<MonetaryAmount>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalBookEvent {
    pub event_id: String,
    pub kind: CapitalBookEventKind,
    pub occurred_at: u64,
    pub source_id: String,
    pub owner_role: CapitalBookRole,
    pub counterparty_role: CapitalBookRole,
    pub counterparty_id: String,
    pub amount: MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facility_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss_event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<CapitalBookEvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalBookSummary {
    pub matching_receipts: u64,
    pub returned_receipts: u64,
    pub matching_facilities: u64,
    pub returned_facilities: u64,
    pub matching_bonds: u64,
    pub returned_bonds: u64,
    pub matching_loss_events: u64,
    pub returned_loss_events: u64,
    pub currencies: Vec<String>,
    pub mixed_currency_book: bool,
    pub funding_sources: u64,
    pub ledger_events: u64,
    pub truncated_receipts: bool,
    pub truncated_facilities: bool,
    pub truncated_bonds: bool,
    pub truncated_loss_events: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalBookReport {
    pub schema: String,
    pub generated_at: u64,
    pub query: CapitalBookQuery,
    pub subject_key: String,
    pub support_boundary: CapitalBookSupportBoundary,
    pub summary: CapitalBookSummary,
    pub sources: Vec<CapitalBookSource>,
    pub events: Vec<CapitalBookEvent>,
}

pub type SignedCapitalBookReport = SignedExportEnvelope<CapitalBookReport>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapitalExecutionInstructionAction {
    LockReserve,
    HoldReserve,
    ReleaseReserve,
    TransferFunds,
    CancelInstruction,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapitalExecutionRole {
    OperatorTreasury,
    ExternalCapitalProvider,
    AgentCounterparty,
    LiabilityProvider,
    Reinsurer,
    FacilityProvider,
    Custodian,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapitalExecutionRailKind {
    Manual,
    Api,
    Ach,
    Wire,
    Ledger,
    Sandbox,
    Web3,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapitalExecutionIntendedState {
    PendingExecution,
    CancellationPending,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapitalExecutionReconciledState {
    NotObserved,
    Matched,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalExecutionAuthorityStep {
    pub role: CapitalExecutionRole,
    pub principal_id: String,
    pub approved_at: u64,
    pub expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalExecutionWindow {
    pub not_before: u64,
    pub not_after: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalExecutionRail {
    pub kind: CapitalExecutionRailKind,
    pub rail_id: String,
    pub custody_provider_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_account_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_account_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalExecutionObservation {
    pub observed_at: u64,
    pub external_reference_id: String,
    pub amount: MonetaryAmount,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalExecutionInstructionSupportBoundary {
    pub capital_book_authoritative: bool,
    pub external_execution_authoritative: bool,
    pub automatic_dispatch_supported: bool,
    pub custody_neutral_instruction_supported: bool,
}

impl Default for CapitalExecutionInstructionSupportBoundary {
    fn default() -> Self {
        Self {
            capital_book_authoritative: true,
            external_execution_authoritative: false,
            automatic_dispatch_supported: false,
            custody_neutral_instruction_supported: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalExecutionInstructionArtifact {
    pub schema: String,
    pub instruction_id: String,
    pub issued_at: u64,
    pub query: CapitalBookQuery,
    pub subject_key: String,
    pub source_id: String,
    pub source_kind: CapitalBookSourceKind,
    pub action: CapitalExecutionInstructionAction,
    pub owner_role: CapitalExecutionRole,
    pub counterparty_role: CapitalExecutionRole,
    pub counterparty_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<MonetaryAmount>,
    pub authority_chain: Vec<CapitalExecutionAuthorityStep>,
    pub execution_window: CapitalExecutionWindow,
    pub rail: CapitalExecutionRail,
    pub intended_state: CapitalExecutionIntendedState,
    pub reconciled_state: CapitalExecutionReconciledState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related_instruction_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_execution: Option<CapitalExecutionObservation>,
    pub support_boundary: CapitalExecutionInstructionSupportBoundary,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<CapitalBookEvidenceReference>,
    pub description: String,
}

pub type SignedCapitalExecutionInstruction =
    SignedExportEnvelope<CapitalExecutionInstructionArtifact>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapitalAllocationDecisionOutcome {
    Allocate,
    Queue,
    ManualReview,
    Deny,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapitalAllocationDecisionReasonCode {
    MissingGovernedReceipt,
    AmbiguousGovernedReceipt,
    MissingRequestedAmount,
    FacilityManualReview,
    FacilityDenied,
    ManualCapitalSource,
    ReserveBookMissing,
    UtilizationCeilingExceeded,
    ConcentrationCapExceeded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalAllocationInstructionDraft {
    pub source_id: String,
    pub source_kind: CapitalBookSourceKind,
    pub action: CapitalExecutionInstructionAction,
    pub amount: MonetaryAmount,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalAllocationDecisionFinding {
    pub code: CapitalAllocationDecisionReasonCode,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<CapitalBookEvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalAllocationDecisionSupportBoundary {
    pub capital_book_authoritative: bool,
    pub simulation_first_only: bool,
    pub automatic_dispatch_supported: bool,
    pub external_execution_authoritative: bool,
}

impl Default for CapitalAllocationDecisionSupportBoundary {
    fn default() -> Self {
        Self {
            capital_book_authoritative: true,
            simulation_first_only: true,
            automatic_dispatch_supported: false,
            external_execution_authoritative: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalAllocationDecisionArtifact {
    pub schema: String,
    pub allocation_id: String,
    pub issued_at: u64,
    pub query: CapitalBookQuery,
    pub subject_key: String,
    pub governed_receipt_id: String,
    pub intent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_token_id: Option<String>,
    pub capability_id: String,
    pub tool_server: String,
    pub tool_name: String,
    pub requested_amount: MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facility_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_kind: Option<CapitalBookSourceKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserve_source_id: Option<String>,
    pub outcome: CapitalAllocationDecisionOutcome,
    pub authority_chain: Vec<CapitalExecutionAuthorityStep>,
    pub execution_window: CapitalExecutionWindow,
    pub rail: CapitalExecutionRail,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_outstanding_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projected_outstanding_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_reserve_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_reserve_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserve_delta_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utilization_ceiling_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concentration_cap_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instruction_drafts: Vec<CapitalAllocationInstructionDraft>,
    pub support_boundary: CapitalAllocationDecisionSupportBoundary,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<CapitalAllocationDecisionFinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<CapitalBookEvidenceReference>,
    pub description: String,
}

pub type SignedCapitalAllocationDecision = SignedExportEnvelope<CapitalAllocationDecisionArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondedExecutionSimulationQuery {
    pub bond_id: String,
    pub autonomy_tier: GovernedAutonomyTier,
    pub runtime_assurance_tier: RuntimeAssuranceTier,
    pub call_chain_present: bool,
}

impl CreditBondedExecutionSimulationQuery {
    pub fn validate(&self) -> Result<(), String> {
        if self.bond_id.trim().is_empty() {
            return Err("bonded execution simulation requires --bond-id".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondedExecutionControlPolicy {
    pub version: String,
    pub kill_switch: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_autonomy_tier: Option<GovernedAutonomyTier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_runtime_assurance_tier: Option<RuntimeAssuranceTier>,
    pub require_delegated_call_chain: bool,
    pub require_locked_reserve: bool,
    pub deny_if_bond_not_active: bool,
    pub deny_if_outstanding_delinquency: bool,
}

impl Default for CreditBondedExecutionControlPolicy {
    fn default() -> Self {
        Self {
            version: "arc.credit.bonded-execution-control-policy.default.v1".to_string(),
            kill_switch: false,
            maximum_autonomy_tier: None,
            minimum_runtime_assurance_tier: None,
            require_delegated_call_chain: true,
            require_locked_reserve: false,
            deny_if_bond_not_active: true,
            deny_if_outstanding_delinquency: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditBondedExecutionDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditBondedExecutionFindingCode {
    KillSwitchEnabled,
    AutonomyGatingUnsupported,
    BondNotActive,
    BondDispositionUnsupported,
    ActiveFacilityUnavailable,
    RuntimePrerequisiteUnmet,
    CertificationPrerequisiteUnmet,
    RuntimeAssuranceBelowAutonomyMinimum,
    RuntimeAssuranceBelowPolicyMinimum,
    MissingDelegatedCallChain,
    AutonomyTierAbovePolicyMaximum,
    ReserveNotLocked,
    OutstandingDelinquency,
    LossLifecycleHistoryTruncated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondedExecutionFinding {
    pub code: CreditBondedExecutionFindingCode,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<CreditScorecardEvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondedExecutionSupportBoundary {
    pub operator_control_policy_supported: bool,
    pub kill_switch_supported: bool,
    pub sandbox_simulation_supported: bool,
    pub external_escrow_execution_supported: bool,
}

impl Default for CreditBondedExecutionSupportBoundary {
    fn default() -> Self {
        Self {
            operator_control_policy_supported: true,
            kill_switch_supported: true,
            sandbox_simulation_supported: true,
            external_escrow_execution_supported: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondedExecutionEvaluation {
    pub decision: CreditBondedExecutionDecision,
    pub autonomy_tier: GovernedAutonomyTier,
    pub runtime_assurance_tier: RuntimeAssuranceTier,
    pub bond_lifecycle_state: CreditBondLifecycleState,
    pub bond_disposition: CreditBondDisposition,
    pub sandbox_integration_ready: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outstanding_delinquency_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<CreditBondedExecutionFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondedExecutionSimulationDelta {
    pub decision_changed: bool,
    pub sandbox_integration_changed: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondedExecutionSimulationRequest {
    pub query: CreditBondedExecutionSimulationQuery,
    pub policy: CreditBondedExecutionControlPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondedExecutionSimulationReport {
    pub schema: String,
    pub generated_at: u64,
    pub query: CreditBondedExecutionSimulationQuery,
    pub policy: CreditBondedExecutionControlPolicy,
    pub support_boundary: CreditBondedExecutionSupportBoundary,
    pub bond: SignedCreditBond,
    pub default_evaluation: CreditBondedExecutionEvaluation,
    pub simulated_evaluation: CreditBondedExecutionEvaluation,
    pub delta: CreditBondedExecutionSimulationDelta,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    #[test]
    fn exposure_ledger_query_clamps_limits() {
        let query = ExposureLedgerQuery {
            receipt_limit: Some(5_000),
            decision_limit: Some(9_000),
            ..ExposureLedgerQuery::default()
        };

        assert_eq!(
            query.receipt_limit_or_default(),
            MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT
        );
        assert_eq!(
            query.decision_limit_or_default(),
            MAX_EXPOSURE_LEDGER_DECISION_LIMIT
        );
        let normalized = query.normalized();
        assert_eq!(
            normalized.receipt_limit,
            Some(MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT)
        );
        assert_eq!(
            normalized.decision_limit,
            Some(MAX_EXPOSURE_LEDGER_DECISION_LIMIT)
        );
    }

    #[test]
    fn exposure_ledger_query_requires_anchor() {
        let query = ExposureLedgerQuery::default();
        assert!(query
            .validate()
            .unwrap_err()
            .contains("require at least one anchor"));
    }

    #[test]
    fn exposure_ledger_query_requires_tool_server_when_tool_name_present() {
        let query = ExposureLedgerQuery {
            agent_subject: Some("subject-1".to_string()),
            tool_name: Some("transfer".to_string()),
            ..ExposureLedgerQuery::default()
        };
        assert!(query
            .validate()
            .unwrap_err()
            .contains("must also specify --tool-server"));
    }

    #[test]
    fn exposure_ledger_query_rejects_inverted_time_window() {
        let query = ExposureLedgerQuery {
            agent_subject: Some("subject-1".to_string()),
            since: Some(20),
            until: Some(10),
            ..ExposureLedgerQuery::default()
        };
        assert!(query
            .validate()
            .unwrap_err()
            .contains("less than or equal to --until"));
    }

    #[test]
    fn credit_backtest_query_requires_subject_scope() {
        let query = CreditBacktestQuery {
            capability_id: Some("cap-1".to_string()),
            ..CreditBacktestQuery::default()
        };
        assert!(query
            .validate()
            .unwrap_err()
            .contains("require --agent-subject"));
    }

    #[test]
    fn credit_backtest_query_clamps_limits() {
        let query = CreditBacktestQuery {
            agent_subject: Some("subject-1".to_string()),
            receipt_limit: Some(5_000),
            decision_limit: Some(9_000),
            window_count: Some(999),
            stale_after_seconds: Some(0),
            window_seconds: Some(0),
            ..CreditBacktestQuery::default()
        };
        let normalized = query.normalized();
        assert_eq!(
            normalized.receipt_limit,
            Some(MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT)
        );
        assert_eq!(
            normalized.decision_limit,
            Some(MAX_EXPOSURE_LEDGER_DECISION_LIMIT)
        );
        assert_eq!(
            normalized.window_count,
            Some(MAX_CREDIT_BACKTEST_WINDOW_LIMIT)
        );
        assert_eq!(normalized.window_seconds, Some(1));
        assert_eq!(normalized.stale_after_seconds, Some(1));
    }

    #[test]
    fn provider_risk_package_query_requires_subject_scope() {
        let query = CreditProviderRiskPackageQuery {
            capability_id: Some("cap-1".to_string()),
            ..CreditProviderRiskPackageQuery::default()
        };
        assert!(query
            .validate()
            .unwrap_err()
            .contains("require --agent-subject"));
    }

    #[test]
    fn provider_risk_package_query_clamps_recent_loss_limit() {
        let query = CreditProviderRiskPackageQuery {
            agent_subject: Some("subject-1".to_string()),
            recent_loss_limit: Some(999),
            ..CreditProviderRiskPackageQuery::default()
        };
        let normalized = query.normalized();
        assert_eq!(
            normalized.recent_loss_limit,
            Some(MAX_CREDIT_PROVIDER_LOSS_LIMIT)
        );
    }

    #[test]
    fn capital_book_query_requires_subject_scope() {
        let query = CapitalBookQuery {
            capability_id: Some("cap-1".to_string()),
            ..CapitalBookQuery::default()
        };
        assert!(query.validate().unwrap_err().contains("--agent-subject"));
    }

    #[test]
    fn capital_book_query_clamps_limits() {
        let query = CapitalBookQuery {
            agent_subject: Some("subject-1".to_string()),
            receipt_limit: Some(5_000),
            facility_limit: Some(999),
            bond_limit: Some(999),
            loss_event_limit: Some(999),
            ..CapitalBookQuery::default()
        };
        let normalized = query.normalized();
        assert_eq!(
            normalized.receipt_limit,
            Some(MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT)
        );
        assert_eq!(
            normalized.facility_limit,
            Some(MAX_CREDIT_FACILITY_LIST_LIMIT)
        );
        assert_eq!(normalized.bond_limit, Some(MAX_CREDIT_BOND_LIST_LIMIT));
        assert_eq!(
            normalized.loss_event_limit,
            Some(MAX_CREDIT_LOSS_LIFECYCLE_LIST_LIMIT)
        );
    }

    #[test]
    fn bonded_execution_simulation_query_requires_bond_id() {
        let query = CreditBondedExecutionSimulationQuery {
            bond_id: "   ".to_string(),
            autonomy_tier: GovernedAutonomyTier::Delegated,
            runtime_assurance_tier: RuntimeAssuranceTier::Attested,
            call_chain_present: true,
        };
        assert!(query.validate().unwrap_err().contains("--bond-id"));
    }

    #[test]
    fn bonded_execution_control_policy_defaults_fail_closed() {
        let policy = CreditBondedExecutionControlPolicy::default();
        assert!(!policy.kill_switch);
        assert!(policy.require_delegated_call_chain);
        assert!(policy.deny_if_bond_not_active);
        assert!(policy.deny_if_outstanding_delinquency);
    }

    #[test]
    fn credit_bond_list_query_clamps_limit() {
        let query = CreditBondListQuery {
            agent_subject: Some("subject-1".to_string()),
            limit: Some(9_999),
            ..CreditBondListQuery::default()
        };
        let normalized = query.normalized();
        assert_eq!(normalized.limit, Some(MAX_CREDIT_BOND_LIST_LIMIT));
    }

    #[test]
    fn credit_bond_round_trip_signature_verifies() {
        let keypair = Keypair::generate();
        let envelope = SignedCreditBond::sign(
            CreditBondArtifact {
                schema: CREDIT_BOND_ARTIFACT_SCHEMA.to_string(),
                bond_id: "cbd-1".to_string(),
                issued_at: 10,
                expires_at: 20,
                lifecycle_state: CreditBondLifecycleState::Active,
                supersedes_bond_id: None,
                report: CreditBondReport {
                    schema: CREDIT_BOND_REPORT_SCHEMA.to_string(),
                    generated_at: 10,
                    filters: ExposureLedgerQuery {
                        agent_subject: Some("subject-1".to_string()),
                        ..ExposureLedgerQuery::default()
                    },
                    exposure: ExposureLedgerSummary {
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
                    scorecard: CreditScorecardSummary {
                        matching_receipts: 1,
                        returned_receipts: 1,
                        matching_decisions: 0,
                        returned_decisions: 0,
                        currencies: vec!["USD".to_string()],
                        mixed_currency_book: false,
                        confidence: CreditScorecardConfidence::High,
                        band: CreditScorecardBand::Prime,
                        overall_score: 0.95,
                        anomaly_count: 0,
                        probationary: false,
                    },
                    disposition: CreditBondDisposition::Hold,
                    prerequisites: CreditBondPrerequisites {
                        active_facility_required: false,
                        active_facility_met: true,
                        runtime_assurance_met: true,
                        certification_required: false,
                        certification_met: true,
                        currency_coherent: true,
                    },
                    support_boundary: CreditBondSupportBoundary::default(),
                    latest_facility_id: Some("cfd-1".to_string()),
                    terms: Some(CreditBondTerms {
                        facility_id: "cfd-1".to_string(),
                        credit_limit: MonetaryAmount {
                            units: 4_000,
                            currency: "USD".to_string(),
                        },
                        collateral_amount: MonetaryAmount {
                            units: 400,
                            currency: "USD".to_string(),
                        },
                        reserve_requirement_amount: MonetaryAmount {
                            units: 400,
                            currency: "USD".to_string(),
                        },
                        outstanding_exposure_amount: MonetaryAmount {
                            units: 0,
                            currency: "USD".to_string(),
                        },
                        reserve_ratio_bps: 1_000,
                        coverage_ratio_bps: 10_000,
                        capital_source: CreditFacilityCapitalSource::OperatorInternal,
                    }),
                    findings: vec![CreditBondFinding {
                        code: CreditBondReasonCode::ReserveHeld,
                        description: "reserve state is held".to_string(),
                        evidence_refs: Vec::new(),
                    }],
                },
            },
            &keypair,
        )
        .unwrap();

        assert!(envelope.verify_signature().unwrap());
        let restored: SignedCreditBond =
            serde_json::from_str(&serde_json::to_string(&envelope).unwrap()).unwrap();
        assert!(restored.verify_signature().unwrap());
    }

    #[test]
    fn provider_risk_package_round_trip_signature_verifies() {
        let keypair = Keypair::generate();
        let exposure = SignedExposureLedgerReport::sign(
            ExposureLedgerReport {
                schema: EXPOSURE_LEDGER_SCHEMA.to_string(),
                generated_at: 1,
                filters: ExposureLedgerQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..ExposureLedgerQuery::default()
                },
                support_boundary: ExposureLedgerSupportBoundary::default(),
                summary: ExposureLedgerSummary {
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
                positions: vec![ExposureLedgerCurrencyPosition {
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
        .unwrap();
        let scorecard = SignedCreditScorecardReport::sign(
            CreditScorecardReport {
                schema: CREDIT_SCORECARD_SCHEMA.to_string(),
                generated_at: 2,
                filters: ExposureLedgerQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..ExposureLedgerQuery::default()
                },
                support_boundary: CreditScorecardSupportBoundary::default(),
                summary: CreditScorecardSummary {
                    matching_receipts: 1,
                    returned_receipts: 1,
                    matching_decisions: 0,
                    returned_decisions: 0,
                    currencies: vec!["USD".to_string()],
                    mixed_currency_book: false,
                    confidence: CreditScorecardConfidence::High,
                    band: CreditScorecardBand::Prime,
                    overall_score: 0.95,
                    anomaly_count: 0,
                    probationary: false,
                },
                reputation: CreditScorecardReputationContext {
                    effective_score: 0.95,
                    probationary: false,
                    resolved_tier: None,
                    imported_signal_count: 0,
                    accepted_imported_signal_count: 0,
                },
                positions: exposure.body.positions.clone(),
                probation: CreditScorecardProbationStatus {
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
        .unwrap();
        let envelope = SignedCreditProviderRiskPackage::sign(
            CreditProviderRiskPackage {
                schema: CREDIT_PROVIDER_RISK_PACKAGE_SCHEMA.to_string(),
                generated_at: 3,
                subject_key: "subject-1".to_string(),
                filters: CreditProviderRiskPackageQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..CreditProviderRiskPackageQuery::default()
                },
                support_boundary: CreditProviderRiskPackageSupportBoundary::default(),
                exposure,
                scorecard,
                facility_report: CreditFacilityReport {
                    schema: CREDIT_FACILITY_REPORT_SCHEMA.to_string(),
                    generated_at: 3,
                    filters: ExposureLedgerQuery {
                        agent_subject: Some("subject-1".to_string()),
                        ..ExposureLedgerQuery::default()
                    },
                    scorecard: CreditScorecardSummary {
                        matching_receipts: 1,
                        returned_receipts: 1,
                        matching_decisions: 0,
                        returned_decisions: 0,
                        currencies: vec!["USD".to_string()],
                        mixed_currency_book: false,
                        confidence: CreditScorecardConfidence::High,
                        band: CreditScorecardBand::Prime,
                        overall_score: 0.95,
                        anomaly_count: 0,
                        probationary: false,
                    },
                    disposition: CreditFacilityDisposition::Grant,
                    prerequisites: CreditFacilityPrerequisites {
                        minimum_runtime_assurance_tier: RuntimeAssuranceTier::Verified,
                        runtime_assurance_met: true,
                        certification_required: false,
                        certification_met: true,
                        manual_review_required: false,
                    },
                    support_boundary: CreditFacilitySupportBoundary::default(),
                    terms: Some(CreditFacilityTerms {
                        credit_limit: MonetaryAmount {
                            units: 4_000,
                            currency: "USD".to_string(),
                        },
                        utilization_ceiling_bps: 8_000,
                        reserve_ratio_bps: 1_500,
                        concentration_cap_bps: 3_000,
                        ttl_seconds: 86_400,
                        capital_source: CreditFacilityCapitalSource::OperatorInternal,
                    }),
                    findings: Vec::new(),
                },
                latest_facility: Some(CreditProviderFacilitySnapshot {
                    facility_id: "cfd-1".to_string(),
                    issued_at: 3,
                    expires_at: 4,
                    disposition: CreditFacilityDisposition::Grant,
                    lifecycle_state: CreditFacilityLifecycleState::Active,
                    credit_limit: Some(MonetaryAmount {
                        units: 4_000,
                        currency: "USD".to_string(),
                    }),
                    supersedes_facility_id: None,
                    signer_key: keypair.public_key().to_hex(),
                }),
                runtime_assurance: Some(CreditRuntimeAssuranceState {
                    governed_receipts: 1,
                    runtime_assurance_receipts: 1,
                    highest_tier: Some(RuntimeAssuranceTier::Verified),
                    latest_schema: Some("arc.runtime-attestation.azure-maa.jwt.v1".to_string()),
                    latest_verifier_family: Some(AttestationVerifierFamily::AzureMaa),
                    latest_verifier: Some("verifier.arc".to_string()),
                    latest_evidence_sha256: Some("sha256-runtime".to_string()),
                    observed_verifier_families: vec![AttestationVerifierFamily::AzureMaa],
                    stale: false,
                }),
                certification: CreditCertificationState {
                    required: false,
                    state: None,
                    artifact_id: None,
                    checked_at: None,
                    published_at: None,
                },
                recent_loss_history: CreditRecentLossHistory {
                    summary: CreditRecentLossSummary {
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
        .unwrap();

        assert!(envelope.verify_signature().unwrap());
        let restored: SignedCreditProviderRiskPackage =
            serde_json::from_str(&serde_json::to_string(&envelope).unwrap()).unwrap();
        assert!(restored.verify_signature().unwrap());
    }

    #[test]
    fn capital_book_round_trip_signature_verifies() {
        let keypair = Keypair::generate();
        let envelope = SignedCapitalBookReport::sign(
            CapitalBookReport {
                schema: CAPITAL_BOOK_REPORT_SCHEMA.to_string(),
                generated_at: 10,
                query: CapitalBookQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..CapitalBookQuery::default()
                },
                subject_key: "subject-1".to_string(),
                support_boundary: CapitalBookSupportBoundary::default(),
                summary: CapitalBookSummary {
                    matching_receipts: 1,
                    returned_receipts: 1,
                    matching_facilities: 1,
                    returned_facilities: 1,
                    matching_bonds: 1,
                    returned_bonds: 1,
                    matching_loss_events: 1,
                    returned_loss_events: 1,
                    currencies: vec!["USD".to_string()],
                    mixed_currency_book: false,
                    funding_sources: 2,
                    ledger_events: 3,
                    truncated_receipts: false,
                    truncated_facilities: false,
                    truncated_bonds: false,
                    truncated_loss_events: false,
                },
                sources: vec![
                    CapitalBookSource {
                        source_id: "capital-source:facility:cfd-1".to_string(),
                        kind: CapitalBookSourceKind::FacilityCommitment,
                        owner_role: CapitalBookRole::OperatorTreasury,
                        counterparty_role: CapitalBookRole::AgentCounterparty,
                        counterparty_id: "subject-1".to_string(),
                        currency: "USD".to_string(),
                        jurisdiction: None,
                        capital_source: Some(CreditFacilityCapitalSource::OperatorInternal),
                        facility_id: Some("cfd-1".to_string()),
                        bond_id: Some("cbd-1".to_string()),
                        committed_amount: Some(MonetaryAmount {
                            units: 4_000,
                            currency: "USD".to_string(),
                        }),
                        held_amount: None,
                        drawn_amount: Some(MonetaryAmount {
                            units: 500,
                            currency: "USD".to_string(),
                        }),
                        disbursed_amount: Some(MonetaryAmount {
                            units: 2_000,
                            currency: "USD".to_string(),
                        }),
                        released_amount: None,
                        repaid_amount: None,
                        impaired_amount: None,
                        description: "facility source".to_string(),
                    },
                    CapitalBookSource {
                        source_id: "capital-source:bond:cbd-1".to_string(),
                        kind: CapitalBookSourceKind::ReserveBook,
                        owner_role: CapitalBookRole::OperatorTreasury,
                        counterparty_role: CapitalBookRole::AgentCounterparty,
                        counterparty_id: "subject-1".to_string(),
                        currency: "USD".to_string(),
                        jurisdiction: None,
                        capital_source: Some(CreditFacilityCapitalSource::OperatorInternal),
                        facility_id: Some("cfd-1".to_string()),
                        bond_id: Some("cbd-1".to_string()),
                        committed_amount: None,
                        held_amount: Some(MonetaryAmount {
                            units: 400,
                            currency: "USD".to_string(),
                        }),
                        drawn_amount: None,
                        disbursed_amount: None,
                        released_amount: Some(MonetaryAmount {
                            units: 50,
                            currency: "USD".to_string(),
                        }),
                        repaid_amount: Some(MonetaryAmount {
                            units: 200,
                            currency: "USD".to_string(),
                        }),
                        impaired_amount: Some(MonetaryAmount {
                            units: 300,
                            currency: "USD".to_string(),
                        }),
                        description: "bond source".to_string(),
                    },
                ],
                events: vec![CapitalBookEvent {
                    event_id: "commit:cfd-1".to_string(),
                    kind: CapitalBookEventKind::Commit,
                    occurred_at: 10,
                    source_id: "capital-source:facility:cfd-1".to_string(),
                    owner_role: CapitalBookRole::OperatorTreasury,
                    counterparty_role: CapitalBookRole::AgentCounterparty,
                    counterparty_id: "subject-1".to_string(),
                    amount: MonetaryAmount {
                        units: 4_000,
                        currency: "USD".to_string(),
                    },
                    facility_id: Some("cfd-1".to_string()),
                    bond_id: None,
                    loss_event_id: None,
                    receipt_id: None,
                    description: "commit".to_string(),
                    evidence_refs: vec![CapitalBookEvidenceReference {
                        kind: CapitalBookEvidenceKind::CreditFacility,
                        reference_id: "cfd-1".to_string(),
                        observed_at: Some(10),
                        locator: Some("credit-facility:cfd-1".to_string()),
                    }],
                }],
            },
            &keypair,
        )
        .unwrap();

        assert!(envelope.verify_signature().unwrap());
        let restored: SignedCapitalBookReport =
            serde_json::from_str(&serde_json::to_string(&envelope).unwrap()).unwrap();
        assert!(restored.verify_signature().unwrap());
    }

    #[test]
    fn capital_execution_instruction_round_trip_signature_verifies() {
        let keypair = Keypair::generate();
        let envelope = SignedCapitalExecutionInstruction::sign(
            CapitalExecutionInstructionArtifact {
                schema: CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA.to_string(),
                instruction_id: "cei-1".to_string(),
                issued_at: 10,
                query: CapitalBookQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..CapitalBookQuery::default()
                },
                subject_key: "subject-1".to_string(),
                source_id: "capital-source:bond:cbd-1".to_string(),
                source_kind: CapitalBookSourceKind::ReserveBook,
                action: CapitalExecutionInstructionAction::LockReserve,
                owner_role: CapitalExecutionRole::OperatorTreasury,
                counterparty_role: CapitalExecutionRole::AgentCounterparty,
                counterparty_id: "subject-1".to_string(),
                amount: Some(MonetaryAmount {
                    units: 400,
                    currency: "USD".to_string(),
                }),
                authority_chain: vec![
                    CapitalExecutionAuthorityStep {
                        role: CapitalExecutionRole::OperatorTreasury,
                        principal_id: "treasury-1".to_string(),
                        approved_at: 9,
                        expires_at: 20,
                        note: None,
                    },
                    CapitalExecutionAuthorityStep {
                        role: CapitalExecutionRole::Custodian,
                        principal_id: "custodian-1".to_string(),
                        approved_at: 9,
                        expires_at: 20,
                        note: None,
                    },
                ],
                execution_window: CapitalExecutionWindow {
                    not_before: 10,
                    not_after: 20,
                },
                rail: CapitalExecutionRail {
                    kind: CapitalExecutionRailKind::Manual,
                    rail_id: "rail-1".to_string(),
                    custody_provider_id: "custodian-1".to_string(),
                    source_account_ref: Some("reserve-main".to_string()),
                    destination_account_ref: None,
                    jurisdiction: Some("US-NY".to_string()),
                },
                intended_state: CapitalExecutionIntendedState::PendingExecution,
                reconciled_state: CapitalExecutionReconciledState::Matched,
                related_instruction_id: None,
                observed_execution: Some(CapitalExecutionObservation {
                    observed_at: 12,
                    external_reference_id: "wire-1".to_string(),
                    amount: MonetaryAmount {
                        units: 400,
                        currency: "USD".to_string(),
                    },
                }),
                support_boundary: CapitalExecutionInstructionSupportBoundary::default(),
                evidence_refs: vec![CapitalBookEvidenceReference {
                    kind: CapitalBookEvidenceKind::CreditBond,
                    reference_id: "cbd-1".to_string(),
                    observed_at: Some(10),
                    locator: Some("credit-bond:cbd-1".to_string()),
                }],
                description: "lock reserve".to_string(),
            },
            &keypair,
        )
        .unwrap();

        assert!(envelope.verify_signature().unwrap());
        let restored: SignedCapitalExecutionInstruction =
            serde_json::from_str(&serde_json::to_string(&envelope).unwrap()).unwrap();
        assert!(restored.verify_signature().unwrap());
    }

    #[test]
    fn capital_allocation_decision_round_trip_signature_verifies() {
        let keypair = Keypair::generate();
        let envelope = SignedCapitalAllocationDecision::sign(
            CapitalAllocationDecisionArtifact {
                schema: CAPITAL_ALLOCATION_DECISION_ARTIFACT_SCHEMA.to_string(),
                allocation_id: "cad-1".to_string(),
                issued_at: 10,
                query: CapitalBookQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..CapitalBookQuery::default()
                },
                subject_key: "subject-1".to_string(),
                governed_receipt_id: "rc-1".to_string(),
                intent_id: "intent-1".to_string(),
                approval_token_id: Some("approval-1".to_string()),
                capability_id: "cap-1".to_string(),
                tool_server: "ledger".to_string(),
                tool_name: "transfer".to_string(),
                requested_amount: MonetaryAmount {
                    units: 300,
                    currency: "USD".to_string(),
                },
                facility_id: Some("cfd-1".to_string()),
                bond_id: Some("cbd-1".to_string()),
                source_id: Some("capital-source:facility:cfd-1".to_string()),
                source_kind: Some(CapitalBookSourceKind::FacilityCommitment),
                reserve_source_id: Some("capital-source:bond:cbd-1".to_string()),
                outcome: CapitalAllocationDecisionOutcome::Allocate,
                authority_chain: vec![
                    CapitalExecutionAuthorityStep {
                        role: CapitalExecutionRole::OperatorTreasury,
                        principal_id: "treasury-1".to_string(),
                        approved_at: 9,
                        expires_at: 20,
                        note: None,
                    },
                    CapitalExecutionAuthorityStep {
                        role: CapitalExecutionRole::Custodian,
                        principal_id: "custodian-1".to_string(),
                        approved_at: 9,
                        expires_at: 20,
                        note: None,
                    },
                ],
                execution_window: CapitalExecutionWindow {
                    not_before: 10,
                    not_after: 20,
                },
                rail: CapitalExecutionRail {
                    kind: CapitalExecutionRailKind::Manual,
                    rail_id: "rail-1".to_string(),
                    custody_provider_id: "custodian-1".to_string(),
                    source_account_ref: Some("facility-main".to_string()),
                    destination_account_ref: Some("merchant-1".to_string()),
                    jurisdiction: Some("US-NY".to_string()),
                },
                current_outstanding_amount: Some(MonetaryAmount {
                    units: 300,
                    currency: "USD".to_string(),
                }),
                projected_outstanding_amount: Some(MonetaryAmount {
                    units: 300,
                    currency: "USD".to_string(),
                }),
                current_reserve_amount: Some(MonetaryAmount {
                    units: 50,
                    currency: "USD".to_string(),
                }),
                required_reserve_amount: Some(MonetaryAmount {
                    units: 50,
                    currency: "USD".to_string(),
                }),
                reserve_delta_amount: None,
                utilization_ceiling_amount: Some(MonetaryAmount {
                    units: 900,
                    currency: "USD".to_string(),
                }),
                concentration_cap_amount: Some(MonetaryAmount {
                    units: 350,
                    currency: "USD".to_string(),
                }),
                instruction_drafts: vec![CapitalAllocationInstructionDraft {
                    source_id: "capital-source:facility:cfd-1".to_string(),
                    source_kind: CapitalBookSourceKind::FacilityCommitment,
                    action: CapitalExecutionInstructionAction::TransferFunds,
                    amount: MonetaryAmount {
                        units: 300,
                        currency: "USD".to_string(),
                    },
                    description: "transfer approved funds".to_string(),
                }],
                support_boundary: CapitalAllocationDecisionSupportBoundary::default(),
                findings: Vec::new(),
                evidence_refs: vec![CapitalBookEvidenceReference {
                    kind: CapitalBookEvidenceKind::Receipt,
                    reference_id: "rc-1".to_string(),
                    observed_at: Some(10),
                    locator: Some("receipt:rc-1".to_string()),
                }],
                description: "allocate governed action".to_string(),
            },
            &keypair,
        )
        .unwrap();

        assert!(envelope.verify_signature().unwrap());
        let restored: SignedCapitalAllocationDecision =
            serde_json::from_str(&serde_json::to_string(&envelope).unwrap()).unwrap();
        assert!(restored.verify_signature().unwrap());
    }
}
