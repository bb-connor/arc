use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use arc_core::canonical::canonical_json_bytes;
use arc_core::capability::{ArcScope, CapabilityToken};
use arc_core::crypto::Signature;
use arc_core::receipt::{
    ArcReceipt, ChildRequestReceipt, Decision, FinancialReceiptMetadata,
    GovernedTransactionReceiptMetadata, ReceiptAttributionMetadata, SettlementStatus,
};
use arc_core::session::OperationTerminalState;
use arc_kernel::checkpoint::{KernelCheckpoint, KernelCheckpointBody};
use arc_kernel::cost_attribution::{
    CostAttributionChainHop, CostAttributionQuery, CostAttributionReceiptRow,
    CostAttributionReport, CostAttributionSummary, LeafCostAttributionRow, RootCostAttributionRow,
    MAX_COST_ATTRIBUTION_LIMIT,
};
use arc_kernel::dpop::DPOP_SCHEMA;
use arc_kernel::operator_report::{
    ArcOAuthAuthorizationDiscoveryMetadata, ArcOAuthAuthorizationExampleMapping,
    ArcOAuthAuthorizationMetadataReport, ArcOAuthAuthorizationProfile,
    ArcOAuthAuthorizationReviewPack, ArcOAuthAuthorizationReviewPackRecord,
    ArcOAuthAuthorizationReviewPackSummary, ArcOAuthAuthorizationSupportBoundary,
    AuthorizationContextReport, AuthorizationContextRow, AuthorizationContextSenderConstraint,
    AuthorizationContextSummary, BehavioralFeedGovernedActionSummary,
    BehavioralFeedMeteredBillingRow, BehavioralFeedMeteredBillingSummary, BehavioralFeedQuery,
    BehavioralFeedReceiptRow, BehavioralFeedReceiptSelection, BehavioralFeedSettlementSummary,
    ComplianceReport, GovernedAuthorizationCommerceDetail, GovernedAuthorizationDetail,
    GovernedAuthorizationMeteredBillingDetail, GovernedAuthorizationTransactionContext,
    MeteredBillingEvidenceRecord, MeteredBillingReconciliationReport,
    MeteredBillingReconciliationRow, MeteredBillingReconciliationState,
    MeteredBillingReconciliationSummary, OperatorReportQuery, SettlementReconciliationReport,
    SettlementReconciliationRow, SettlementReconciliationState, SettlementReconciliationSummary,
    SharedEvidenceQuery, SharedEvidenceReferenceReport, SharedEvidenceReferenceRow,
    SharedEvidenceReferenceSummary, ARC_OAUTH_AUTHORIZATION_COMMERCE_DETAIL_TYPE,
    ARC_OAUTH_AUTHORIZATION_CONTEXT_REPORT_SCHEMA, ARC_OAUTH_AUTHORIZATION_METADATA_SCHEMA,
    ARC_OAUTH_AUTHORIZATION_METERED_BILLING_DETAIL_TYPE,
    ARC_OAUTH_AUTHORIZATION_REVIEW_PACK_SCHEMA, ARC_OAUTH_AUTHORIZATION_TOOL_DETAIL_TYPE,
    ARC_OAUTH_SENDER_PROOF_ARC_DPOP,
};
use arc_kernel::receipt_analytics::{
    AgentAnalyticsRow, AnalyticsTimeBucket, ReceiptAnalyticsMetrics, ReceiptAnalyticsQuery,
    ReceiptAnalyticsResponse, TimeAnalyticsRow, ToolAnalyticsRow, MAX_ANALYTICS_GROUP_LIMIT,
};
use arc_kernel::receipt_query::{ReceiptQuery, ReceiptQueryResult, MAX_QUERY_LIMIT};
use arc_kernel::{
    CapabilitySnapshot, CreditBondDisposition, CreditBondLifecycleState, CreditBondListQuery,
    CreditBondListReport, CreditBondListSummary, CreditBondRow, CreditFacilityDisposition,
    CreditFacilityLifecycleState, CreditFacilityListQuery, CreditFacilityListReport,
    CreditFacilityListSummary, CreditFacilityRow, CreditLossLifecycleEventKind,
    CreditLossLifecycleListQuery, CreditLossLifecycleListReport, CreditLossLifecycleListSummary,
    CreditLossLifecycleRow, EvidenceChildReceiptScope, EvidenceExportQuery,
    FederatedEvidenceShareImport, FederatedEvidenceShareSummary, LiabilityAutoBindDisposition,
    LiabilityClaimPayoutReconciliationState, LiabilityClaimResponseDisposition,
    LiabilityClaimSettlementReconciliationState, LiabilityClaimWorkflowQuery,
    LiabilityClaimWorkflowReport, LiabilityClaimWorkflowRow, LiabilityClaimWorkflowSummary,
    LiabilityMarketWorkflowQuery, LiabilityMarketWorkflowReport, LiabilityMarketWorkflowRow,
    LiabilityMarketWorkflowSummary, LiabilityProviderLifecycleState, LiabilityProviderListQuery,
    LiabilityProviderListReport, LiabilityProviderListSummary, LiabilityProviderResolutionQuery,
    LiabilityProviderResolutionReport, LiabilityProviderRow, LiabilityQuoteDisposition,
    ReceiptStore, ReceiptStoreError, RetentionConfig, SignedCreditBond, SignedCreditFacility,
    SignedCreditLossLifecycle, SignedLiabilityAutoBindDecision, SignedLiabilityBoundCoverage,
    SignedLiabilityClaimAdjudication, SignedLiabilityClaimDispute, SignedLiabilityClaimPackage,
    SignedLiabilityClaimPayoutInstruction, SignedLiabilityClaimPayoutReceipt,
    SignedLiabilityClaimResponse, SignedLiabilityClaimSettlementInstruction,
    SignedLiabilityClaimSettlementReceipt, SignedLiabilityPlacement,
    SignedLiabilityPricingAuthority, SignedLiabilityProvider, SignedLiabilityQuoteRequest,
    SignedLiabilityQuoteResponse, SignedUnderwritingDecision, StoredChildReceipt,
    StoredToolReceipt, UnderwritingAppealCreateRequest, UnderwritingAppealRecord,
    UnderwritingAppealResolution, UnderwritingAppealResolveRequest, UnderwritingAppealStatus,
    UnderwritingDecisionLifecycleState, UnderwritingDecisionListReport,
    UnderwritingDecisionOutcome, UnderwritingDecisionQuery, UnderwritingDecisionRow,
    UnderwritingDecisionSummary, CREDIT_BOND_LIST_REPORT_SCHEMA,
    CREDIT_FACILITY_LIST_REPORT_SCHEMA, CREDIT_LOSS_LIFECYCLE_LIST_REPORT_SCHEMA,
    LIABILITY_CLAIM_WORKFLOW_REPORT_SCHEMA, LIABILITY_MARKET_WORKFLOW_REPORT_SCHEMA,
    LIABILITY_PROVIDER_LIST_REPORT_SCHEMA, LIABILITY_PROVIDER_RESOLUTION_REPORT_SCHEMA,
};
use rusqlite::{params, Connection, OptionalExtension};

pub struct SqliteReceiptStore {
    pub(crate) connection: Connection,
}

type FederatedShareSubjectCorpus = (
    FederatedEvidenceShareSummary,
    Vec<StoredToolReceipt>,
    Vec<CapabilitySnapshot>,
);

#[path = "receipt_store/bootstrap.rs"]
mod bootstrap;
#[path = "receipt_store/evidence_retention.rs"]
mod evidence_retention;
#[path = "receipt_store/liability_claims.rs"]
mod liability_claims;
#[path = "receipt_store/liability_market.rs"]
mod liability_market;
#[path = "receipt_store/reports.rs"]
mod reports;
#[path = "receipt_store/support.rs"]
mod support;
#[cfg(test)]
#[path = "receipt_store/tests.rs"]
mod tests;
#[path = "receipt_store/underwriting_credit.rs"]
mod underwriting_credit;

use support::*;
