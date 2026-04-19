use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use arc_core::canonical::canonical_json_bytes;
use arc_core::capability::{ArcScope, CapabilityToken};
use arc_core::crypto::{sha256_hex, Signature};
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
    ComplianceReport, EconomicCompletionFlowReport, EconomicCompletionFlowSummary,
    EconomicReceiptMeteringProjection, EconomicReceiptProjectionReport,
    EconomicReceiptProjectionRow, EconomicReceiptProjectionSummary,
    EconomicReceiptSettlementProjection, GovernedAuthorizationCommerceDetail,
    GovernedAuthorizationDetail, GovernedAuthorizationMeteredBillingDetail,
    GovernedAuthorizationTransactionContext, MeteredBillingEvidenceRecord,
    MeteredBillingReconciliationReport, MeteredBillingReconciliationRow,
    MeteredBillingReconciliationState, MeteredBillingReconciliationSummary,
    OperatorReportQuery, SettlementReconciliationReport, SettlementReconciliationRow,
    SettlementReconciliationState, SettlementReconciliationSummary, SharedEvidenceQuery,
    SharedEvidenceReferenceReport, SharedEvidenceReferenceRow, SharedEvidenceReferenceSummary,
    ARC_OAUTH_AUTHORIZATION_COMMERCE_DETAIL_TYPE,
    ARC_OAUTH_AUTHORIZATION_CONTEXT_REPORT_SCHEMA, ARC_OAUTH_AUTHORIZATION_METADATA_SCHEMA,
    ARC_OAUTH_AUTHORIZATION_METERED_BILLING_DETAIL_TYPE,
    ARC_OAUTH_AUTHORIZATION_REVIEW_PACK_SCHEMA, ARC_OAUTH_AUTHORIZATION_TOOL_DETAIL_TYPE,
    ARC_OAUTH_SENDER_PROOF_ARC_DPOP, ECONOMIC_COMPLETION_FLOW_SCHEMA,
};
use arc_kernel::receipt_analytics::{
    AgentAnalyticsRow, AnalyticsTimeBucket, ReceiptAnalyticsMetrics, ReceiptAnalyticsQuery,
    ReceiptAnalyticsResponse, TimeAnalyticsRow, ToolAnalyticsRow, MAX_ANALYTICS_GROUP_LIMIT,
};
use arc_kernel::receipt_query::{ReceiptQuery, ReceiptQueryResult, MAX_QUERY_LIMIT};
use arc_kernel::receipt_store::{ReceiptLineageStatementLink, ReceiptLineageVerification};
use arc_kernel::{
    CapabilitySnapshot, CreditBondDisposition, CreditBondLifecycleState, CreditBondListQuery,
    CreditBondListReport, CreditBondListSummary, CreditBondRow, CreditFacilityDisposition,
    CreditFacilityLifecycleState, CreditFacilityListQuery, CreditFacilityListReport,
    CreditFacilityListSummary, CreditFacilityRow, CreditLossLifecycleEventKind,
    CreditLossLifecycleListQuery, CreditLossLifecycleListReport, CreditLossLifecycleListSummary,
    CreditLossLifecycleRow, EvidenceChildReceiptScope, EvidenceExportQuery,
    ExposureLedgerQuery,
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
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection, OptionalExtension};

pub struct SqliteReceiptStore {
    pub(crate) pool: Pool<SqliteConnectionManager>,
    /// Phase 1.5 multi-tenant receipt isolation: when true, tenant-
    /// scoped queries exclude the pre-multitenant NULL-tagged set. When
    /// false, queries with `tenant_filter = Some(id)` return rows where
    /// `tenant_id = id OR tenant_id IS NULL`, which keeps legacy
    /// (pre-1.5) receipts visible during explicit compatibility mode.
    pub(crate) strict_tenant_isolation: std::sync::atomic::AtomicBool,
}

type FederatedShareSubjectCorpus = (
    FederatedEvidenceShareSummary,
    Vec<StoredToolReceipt>,
    Vec<CapabilitySnapshot>,
);
pub(crate) type SqliteStoreConnection = PooledConnection<SqliteConnectionManager>;

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

pub(crate) use support::{decode_verified_arc_receipt, decode_verified_child_receipt};
use support::*;

impl SqliteReceiptStore {
    pub(crate) fn connection(&self) -> Result<SqliteStoreConnection, ReceiptStoreError> {
        self.pool
            .get()
            .map_err(|error| ReceiptStoreError::Pool(error.to_string()))
    }

    /// Phase 1.5 multi-tenant receipt isolation: toggle strict-isolation
    /// mode on tenant-scoped queries.
    ///
    /// When `strict = true`, a `tenant_filter = Some(id)` query returns
    /// ONLY rows whose `tenant_id = id`. Legacy pre-1.5 receipts with
    /// `tenant_id IS NULL` are excluded.
    ///
    /// When `strict = false`, the same query also includes rows where
    /// `tenant_id IS NULL` -- the pre-multitenant "public" fallback
    /// set -- so legacy receipts remain visible during an explicit
    /// compatibility window.
    ///
    /// A `tenant_filter = None` admin / compat query always returns
    /// every row regardless of this setting.
    pub fn with_strict_tenant_isolation(&self, strict: bool) {
        self.strict_tenant_isolation
            .store(strict, std::sync::atomic::Ordering::SeqCst);
    }

    /// Read the current strict-tenant-isolation setting.
    #[must_use]
    pub fn strict_tenant_isolation_enabled(&self) -> bool {
        self.strict_tenant_isolation
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}
