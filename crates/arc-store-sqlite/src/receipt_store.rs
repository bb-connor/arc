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
    FederatedEvidenceShareImport, FederatedEvidenceShareSummary, LiabilityClaimResponseDisposition,
    LiabilityClaimWorkflowQuery, LiabilityClaimWorkflowReport, LiabilityClaimWorkflowRow,
    LiabilityClaimWorkflowSummary, LiabilityMarketWorkflowQuery, LiabilityMarketWorkflowReport,
    LiabilityMarketWorkflowRow, LiabilityMarketWorkflowSummary, LiabilityProviderLifecycleState,
    LiabilityProviderListQuery, LiabilityProviderListReport, LiabilityProviderListSummary,
    LiabilityProviderResolutionQuery, LiabilityProviderResolutionReport, LiabilityProviderRow,
    LiabilityQuoteDisposition, ReceiptStore, ReceiptStoreError, RetentionConfig, SignedCreditBond,
    SignedCreditFacility, SignedCreditLossLifecycle, SignedLiabilityBoundCoverage,
    SignedLiabilityClaimAdjudication, SignedLiabilityClaimDispute, SignedLiabilityClaimPackage,
    SignedLiabilityClaimResponse, SignedLiabilityPlacement, SignedLiabilityProvider,
    SignedLiabilityQuoteRequest, SignedLiabilityQuoteResponse, SignedUnderwritingDecision,
    StoredChildReceipt, StoredToolReceipt, UnderwritingAppealCreateRequest,
    UnderwritingAppealRecord, UnderwritingAppealResolution, UnderwritingAppealResolveRequest,
    UnderwritingAppealStatus, UnderwritingDecisionLifecycleState, UnderwritingDecisionListReport,
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

impl SqliteReceiptStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReceiptStoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let connection = Connection::open(path)?;
        connection.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS arc_tool_receipts (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                timestamp INTEGER NOT NULL,
                capability_id TEXT NOT NULL,
                subject_key TEXT,
                issuer_key TEXT,
                grant_index INTEGER,
                tool_server TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                decision_kind TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_arc_tool_receipts_timestamp
                ON arc_tool_receipts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_arc_tool_receipts_capability
                ON arc_tool_receipts(capability_id);
            CREATE INDEX IF NOT EXISTS idx_arc_tool_receipts_subject
                ON arc_tool_receipts(subject_key);
            CREATE INDEX IF NOT EXISTS idx_arc_tool_receipts_grant
                ON arc_tool_receipts(capability_id, grant_index);
            CREATE INDEX IF NOT EXISTS idx_arc_tool_receipts_tool
                ON arc_tool_receipts(tool_server, tool_name);
            CREATE INDEX IF NOT EXISTS idx_arc_tool_receipts_decision
                ON arc_tool_receipts(decision_kind);

            CREATE TABLE IF NOT EXISTS settlement_reconciliations (
                receipt_id TEXT PRIMARY KEY REFERENCES arc_tool_receipts(receipt_id) ON DELETE CASCADE,
                reconciliation_state TEXT NOT NULL,
                note TEXT,
                updated_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_settlement_reconciliations_updated_at
                ON settlement_reconciliations(updated_at);

            CREATE TABLE IF NOT EXISTS metered_billing_reconciliations (
                receipt_id TEXT PRIMARY KEY REFERENCES arc_tool_receipts(receipt_id) ON DELETE CASCADE,
                adapter_kind TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                observed_units INTEGER NOT NULL,
                billed_cost_units INTEGER NOT NULL,
                billed_cost_currency TEXT NOT NULL,
                evidence_sha256 TEXT,
                recorded_at INTEGER NOT NULL,
                reconciliation_state TEXT NOT NULL,
                note TEXT,
                updated_at INTEGER NOT NULL,
                UNIQUE (adapter_kind, evidence_id)
            );
            CREATE INDEX IF NOT EXISTS idx_metered_billing_reconciliations_updated_at
                ON metered_billing_reconciliations(updated_at);

            CREATE TABLE IF NOT EXISTS underwriting_decisions (
                decision_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                capability_id TEXT,
                subject_key TEXT,
                tool_server TEXT,
                tool_name TEXT,
                outcome TEXT NOT NULL,
                lifecycle_state TEXT NOT NULL,
                review_state TEXT NOT NULL,
                risk_class TEXT NOT NULL,
                supersedes_decision_id TEXT REFERENCES underwriting_decisions(decision_id),
                superseded_by_decision_id TEXT REFERENCES underwriting_decisions(decision_id),
                premium_units INTEGER,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_underwriting_decisions_issued_at
                ON underwriting_decisions(issued_at);
            CREATE INDEX IF NOT EXISTS idx_underwriting_decisions_capability
                ON underwriting_decisions(capability_id);
            CREATE INDEX IF NOT EXISTS idx_underwriting_decisions_subject
                ON underwriting_decisions(subject_key);
            CREATE INDEX IF NOT EXISTS idx_underwriting_decisions_tool
                ON underwriting_decisions(tool_server, tool_name);
            CREATE INDEX IF NOT EXISTS idx_underwriting_decisions_outcome
                ON underwriting_decisions(outcome);
            CREATE INDEX IF NOT EXISTS idx_underwriting_decisions_lifecycle
                ON underwriting_decisions(lifecycle_state);

            CREATE TABLE IF NOT EXISTS underwriting_appeals (
                appeal_id TEXT PRIMARY KEY,
                decision_id TEXT NOT NULL REFERENCES underwriting_decisions(decision_id) ON DELETE CASCADE,
                requested_by TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL,
                note TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                resolved_by TEXT,
                replacement_decision_id TEXT REFERENCES underwriting_decisions(decision_id)
            );
            CREATE INDEX IF NOT EXISTS idx_underwriting_appeals_decision
                ON underwriting_appeals(decision_id);
            CREATE INDEX IF NOT EXISTS idx_underwriting_appeals_status
                ON underwriting_appeals(status);
            CREATE INDEX IF NOT EXISTS idx_underwriting_appeals_updated_at
                ON underwriting_appeals(updated_at);

            CREATE TABLE IF NOT EXISTS credit_facilities (
                facility_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                capability_id TEXT,
                subject_key TEXT,
                tool_server TEXT,
                tool_name TEXT,
                disposition TEXT NOT NULL,
                lifecycle_state TEXT NOT NULL,
                supersedes_facility_id TEXT REFERENCES credit_facilities(facility_id),
                superseded_by_facility_id TEXT REFERENCES credit_facilities(facility_id),
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_credit_facilities_issued_at
                ON credit_facilities(issued_at);
            CREATE INDEX IF NOT EXISTS idx_credit_facilities_expires_at
                ON credit_facilities(expires_at);
            CREATE INDEX IF NOT EXISTS idx_credit_facilities_capability
                ON credit_facilities(capability_id);
            CREATE INDEX IF NOT EXISTS idx_credit_facilities_subject
                ON credit_facilities(subject_key);
            CREATE INDEX IF NOT EXISTS idx_credit_facilities_tool
                ON credit_facilities(tool_server, tool_name);
            CREATE INDEX IF NOT EXISTS idx_credit_facilities_disposition
                ON credit_facilities(disposition);
            CREATE INDEX IF NOT EXISTS idx_credit_facilities_lifecycle
                ON credit_facilities(lifecycle_state);

            CREATE TABLE IF NOT EXISTS credit_bonds (
                bond_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                facility_id TEXT,
                capability_id TEXT,
                subject_key TEXT,
                tool_server TEXT,
                tool_name TEXT,
                disposition TEXT NOT NULL,
                lifecycle_state TEXT NOT NULL,
                supersedes_bond_id TEXT REFERENCES credit_bonds(bond_id),
                superseded_by_bond_id TEXT REFERENCES credit_bonds(bond_id),
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_issued_at
                ON credit_bonds(issued_at);
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_expires_at
                ON credit_bonds(expires_at);
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_facility
                ON credit_bonds(facility_id);
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_capability
                ON credit_bonds(capability_id);
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_subject
                ON credit_bonds(subject_key);
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_tool
                ON credit_bonds(tool_server, tool_name);
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_disposition
                ON credit_bonds(disposition);
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_lifecycle
                ON credit_bonds(lifecycle_state);

            CREATE TABLE IF NOT EXISTS liability_providers (
                provider_record_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                provider_id TEXT NOT NULL,
                lifecycle_state TEXT NOT NULL,
                supersedes_provider_record_id TEXT REFERENCES liability_providers(provider_record_id),
                superseded_by_provider_record_id TEXT REFERENCES liability_providers(provider_record_id),
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_providers_issued_at
                ON liability_providers(issued_at);
            CREATE INDEX IF NOT EXISTS idx_liability_providers_provider_id
                ON liability_providers(provider_id);
            CREATE INDEX IF NOT EXISTS idx_liability_providers_lifecycle
                ON liability_providers(lifecycle_state);

            CREATE TABLE IF NOT EXISTS liability_quote_requests (
                quote_request_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                provider_id TEXT NOT NULL,
                jurisdiction TEXT NOT NULL,
                coverage_class TEXT NOT NULL,
                currency TEXT NOT NULL,
                subject_key TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_quote_requests_issued_at
                ON liability_quote_requests(issued_at);
            CREATE INDEX IF NOT EXISTS idx_liability_quote_requests_provider
                ON liability_quote_requests(provider_id);
            CREATE INDEX IF NOT EXISTS idx_liability_quote_requests_subject
                ON liability_quote_requests(subject_key);

            CREATE TABLE IF NOT EXISTS liability_quote_responses (
                quote_response_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                quote_request_id TEXT NOT NULL REFERENCES liability_quote_requests(quote_request_id),
                provider_id TEXT NOT NULL,
                disposition TEXT NOT NULL,
                expires_at INTEGER,
                supersedes_quote_response_id TEXT REFERENCES liability_quote_responses(quote_response_id),
                superseded_by_quote_response_id TEXT REFERENCES liability_quote_responses(quote_response_id),
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_quote_responses_issued_at
                ON liability_quote_responses(issued_at);
            CREATE INDEX IF NOT EXISTS idx_liability_quote_responses_request
                ON liability_quote_responses(quote_request_id);
            CREATE INDEX IF NOT EXISTS idx_liability_quote_responses_provider
                ON liability_quote_responses(provider_id);

            CREATE TABLE IF NOT EXISTS liability_placements (
                placement_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                quote_request_id TEXT NOT NULL REFERENCES liability_quote_requests(quote_request_id),
                quote_response_id TEXT NOT NULL REFERENCES liability_quote_responses(quote_response_id),
                provider_id TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_liability_placements_request
                ON liability_placements(quote_request_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_liability_placements_response
                ON liability_placements(quote_response_id);
            CREATE INDEX IF NOT EXISTS idx_liability_placements_provider
                ON liability_placements(provider_id);

            CREATE TABLE IF NOT EXISTS liability_bound_coverages (
                bound_coverage_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                quote_request_id TEXT NOT NULL REFERENCES liability_quote_requests(quote_request_id),
                quote_response_id TEXT NOT NULL REFERENCES liability_quote_responses(quote_response_id),
                placement_id TEXT NOT NULL REFERENCES liability_placements(placement_id),
                provider_id TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_liability_bound_coverages_request
                ON liability_bound_coverages(quote_request_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_liability_bound_coverages_response
                ON liability_bound_coverages(quote_response_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_liability_bound_coverages_placement
                ON liability_bound_coverages(placement_id);
            CREATE INDEX IF NOT EXISTS idx_liability_bound_coverages_provider
                ON liability_bound_coverages(provider_id);

            CREATE TABLE IF NOT EXISTS liability_claim_packages (
                claim_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                provider_id TEXT NOT NULL,
                policy_number TEXT NOT NULL,
                jurisdiction TEXT NOT NULL,
                subject_key TEXT NOT NULL,
                claim_event_at INTEGER NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_claim_packages_issued_at
                ON liability_claim_packages(issued_at);
            CREATE INDEX IF NOT EXISTS idx_liability_claim_packages_provider
                ON liability_claim_packages(provider_id);
            CREATE INDEX IF NOT EXISTS idx_liability_claim_packages_policy_number
                ON liability_claim_packages(policy_number);
            CREATE INDEX IF NOT EXISTS idx_liability_claim_packages_subject
                ON liability_claim_packages(subject_key);

            CREATE TABLE IF NOT EXISTS liability_claim_responses (
                claim_response_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                claim_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_packages(claim_id),
                provider_id TEXT NOT NULL,
                disposition TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_claim_responses_issued_at
                ON liability_claim_responses(issued_at);
            CREATE INDEX IF NOT EXISTS idx_liability_claim_responses_provider
                ON liability_claim_responses(provider_id);

            CREATE TABLE IF NOT EXISTS liability_claim_disputes (
                dispute_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                claim_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_packages(claim_id),
                claim_response_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_responses(claim_response_id),
                provider_id TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_claim_disputes_issued_at
                ON liability_claim_disputes(issued_at);
            CREATE INDEX IF NOT EXISTS idx_liability_claim_disputes_provider
                ON liability_claim_disputes(provider_id);

            CREATE TABLE IF NOT EXISTS liability_claim_adjudications (
                adjudication_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                claim_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_packages(claim_id),
                dispute_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_disputes(dispute_id),
                outcome TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_claim_adjudications_issued_at
                ON liability_claim_adjudications(issued_at);

            CREATE TABLE IF NOT EXISTS credit_loss_lifecycle (
                event_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                bond_id TEXT NOT NULL REFERENCES credit_bonds(bond_id),
                facility_id TEXT,
                capability_id TEXT,
                subject_key TEXT,
                tool_server TEXT,
                tool_name TEXT,
                event_kind TEXT NOT NULL,
                projected_bond_lifecycle_state TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_credit_loss_lifecycle_issued_at
                ON credit_loss_lifecycle(issued_at);
            CREATE INDEX IF NOT EXISTS idx_credit_loss_lifecycle_bond
                ON credit_loss_lifecycle(bond_id);
            CREATE INDEX IF NOT EXISTS idx_credit_loss_lifecycle_facility
                ON credit_loss_lifecycle(facility_id);
            CREATE INDEX IF NOT EXISTS idx_credit_loss_lifecycle_capability
                ON credit_loss_lifecycle(capability_id);
            CREATE INDEX IF NOT EXISTS idx_credit_loss_lifecycle_subject
                ON credit_loss_lifecycle(subject_key);
            CREATE INDEX IF NOT EXISTS idx_credit_loss_lifecycle_tool
                ON credit_loss_lifecycle(tool_server, tool_name);
            CREATE INDEX IF NOT EXISTS idx_credit_loss_lifecycle_kind
                ON credit_loss_lifecycle(event_kind);

            CREATE TABLE IF NOT EXISTS arc_child_receipts (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                timestamp INTEGER NOT NULL,
                session_id TEXT NOT NULL,
                parent_request_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                operation_kind TEXT NOT NULL,
                terminal_state TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                outcome_hash TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_arc_child_receipts_timestamp
                ON arc_child_receipts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_arc_child_receipts_session
                ON arc_child_receipts(session_id);
            CREATE INDEX IF NOT EXISTS idx_arc_child_receipts_parent
                ON arc_child_receipts(parent_request_id);
            CREATE INDEX IF NOT EXISTS idx_arc_child_receipts_request
                ON arc_child_receipts(request_id);

            CREATE TABLE IF NOT EXISTS kernel_checkpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                checkpoint_seq INTEGER NOT NULL UNIQUE,
                batch_start_seq INTEGER NOT NULL,
                batch_end_seq INTEGER NOT NULL,
                tree_size INTEGER NOT NULL,
                merkle_root TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                statement_json TEXT NOT NULL,
                signature TEXT NOT NULL,
                kernel_key TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_kernel_checkpoints_batch_end
                ON kernel_checkpoints(batch_end_seq);

            CREATE TABLE IF NOT EXISTS capability_lineage (
                capability_id        TEXT PRIMARY KEY,
                subject_key          TEXT NOT NULL,
                issuer_key           TEXT NOT NULL,
                issued_at            INTEGER NOT NULL,
                expires_at           INTEGER NOT NULL,
                grants_json          TEXT NOT NULL,
                delegation_depth     INTEGER NOT NULL DEFAULT 0,
                parent_capability_id TEXT REFERENCES capability_lineage(capability_id)
            );
            CREATE INDEX IF NOT EXISTS idx_capability_lineage_subject
                ON capability_lineage(subject_key);
            CREATE INDEX IF NOT EXISTS idx_capability_lineage_issuer
                ON capability_lineage(issuer_key);
            CREATE INDEX IF NOT EXISTS idx_capability_lineage_issued_at
                ON capability_lineage(issued_at);
            CREATE INDEX IF NOT EXISTS idx_capability_lineage_parent
                ON capability_lineage(parent_capability_id);

            CREATE TABLE IF NOT EXISTS federated_lineage_bridges (
                local_capability_id TEXT PRIMARY KEY REFERENCES capability_lineage(capability_id) ON DELETE CASCADE,
                parent_capability_id TEXT NOT NULL,
                share_id TEXT REFERENCES federated_evidence_shares(share_id)
            );
            CREATE INDEX IF NOT EXISTS idx_federated_lineage_bridges_parent
                ON federated_lineage_bridges(parent_capability_id);

            CREATE TABLE IF NOT EXISTS federated_evidence_shares (
                share_id TEXT PRIMARY KEY,
                manifest_hash TEXT NOT NULL,
                imported_at INTEGER NOT NULL,
                exported_at INTEGER NOT NULL,
                issuer TEXT NOT NULL,
                partner TEXT NOT NULL,
                signer_public_key TEXT NOT NULL,
                require_proofs INTEGER NOT NULL DEFAULT 0,
                query_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_federated_evidence_shares_imported_at
                ON federated_evidence_shares(imported_at);

            CREATE TABLE IF NOT EXISTS federated_share_tool_receipts (
                share_id TEXT NOT NULL REFERENCES federated_evidence_shares(share_id) ON DELETE CASCADE,
                seq INTEGER NOT NULL,
                receipt_id TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                capability_id TEXT NOT NULL,
                subject_key TEXT,
                issuer_key TEXT,
                raw_json TEXT NOT NULL,
                PRIMARY KEY (share_id, seq),
                UNIQUE (share_id, receipt_id)
            );
            CREATE INDEX IF NOT EXISTS idx_federated_share_receipts_capability
                ON federated_share_tool_receipts(capability_id);
            CREATE INDEX IF NOT EXISTS idx_federated_share_receipts_subject
                ON federated_share_tool_receipts(subject_key);

            CREATE TABLE IF NOT EXISTS federated_share_capability_lineage (
                share_id TEXT NOT NULL REFERENCES federated_evidence_shares(share_id) ON DELETE CASCADE,
                capability_id TEXT NOT NULL,
                subject_key TEXT NOT NULL,
                issuer_key TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                grants_json TEXT NOT NULL,
                delegation_depth INTEGER NOT NULL DEFAULT 0,
                parent_capability_id TEXT,
                PRIMARY KEY (share_id, capability_id)
            );
            CREATE INDEX IF NOT EXISTS idx_federated_share_lineage_capability
                ON federated_share_capability_lineage(capability_id);
            CREATE INDEX IF NOT EXISTS idx_federated_share_lineage_subject
                ON federated_share_capability_lineage(subject_key);
            "#,
        )?;
        ensure_tool_receipt_attribution_columns(&connection)?;
        backfill_tool_receipt_attribution_columns(&connection)?;

        Ok(Self { connection })
    }

    pub fn tool_receipt_count(&self) -> Result<u64, ReceiptStoreError> {
        let count =
            self.connection
                .query_row("SELECT COUNT(*) FROM arc_tool_receipts", [], |row| {
                    row.get::<_, u64>(0)
                })?;
        Ok(count)
    }

    pub fn child_receipt_count(&self) -> Result<u64, ReceiptStoreError> {
        let count =
            self.connection
                .query_row("SELECT COUNT(*) FROM arc_child_receipts", [], |row| {
                    row.get::<_, u64>(0)
                })?;
        Ok(count)
    }

    pub fn record_underwriting_decision(
        &mut self,
        decision: &SignedUnderwritingDecision,
    ) -> Result<(), ReceiptStoreError> {
        if !decision
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "underwriting decision signature verification failed".to_string(),
            ));
        }

        let artifact = &decision.body;
        let tx = self.connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT decision_id FROM underwriting_decisions WHERE decision_id = ?1",
                params![artifact.decision_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "underwriting decision `{}` already exists",
                artifact.decision_id
            )));
        }

        if let Some(supersedes_decision_id) = artifact.supersedes_decision_id.as_deref() {
            let state = tx
                .query_row(
                    "SELECT lifecycle_state, superseded_by_decision_id
                     FROM underwriting_decisions
                     WHERE decision_id = ?1",
                    params![supersedes_decision_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
                )
                .optional()?
                .ok_or_else(|| {
                    ReceiptStoreError::NotFound(format!(
                        "superseded underwriting decision `{supersedes_decision_id}` not found"
                    ))
                })?;
            if state.0
                != underwriting_lifecycle_state_label(UnderwritingDecisionLifecycleState::Active)
                || state.1.is_some()
            {
                return Err(ReceiptStoreError::Conflict(format!(
                    "underwriting decision `{supersedes_decision_id}` is not active"
                )));
            }
        }

        let premium_units = artifact
            .premium
            .quoted_amount
            .as_ref()
            .map(|amount| amount.units as i64);
        tx.execute(
            "INSERT INTO underwriting_decisions (
                decision_id, issued_at, capability_id, subject_key, tool_server, tool_name,
                outcome, lifecycle_state, review_state, risk_class, supersedes_decision_id,
                superseded_by_decision_id, premium_units, raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL, ?12, ?13, ?14, ?15)",
            params![
                artifact.decision_id,
                artifact.issued_at as i64,
                artifact.evaluation.input.filters.capability_id.as_deref(),
                artifact.evaluation.input.filters.agent_subject.as_deref(),
                artifact.evaluation.input.filters.tool_server.as_deref(),
                artifact.evaluation.input.filters.tool_name.as_deref(),
                underwriting_decision_outcome_label(artifact.evaluation.outcome),
                underwriting_lifecycle_state_label(artifact.lifecycle_state),
                underwriting_review_state_label(artifact.review_state),
                underwriting_risk_class_label(artifact.evaluation.risk_class),
                artifact.supersedes_decision_id.as_deref(),
                premium_units,
                serde_json::to_string(decision)?,
                decision.signer_key.to_hex(),
                decision.signature.to_hex(),
            ],
        )?;

        if let Some(supersedes_decision_id) = artifact.supersedes_decision_id.as_deref() {
            tx.execute(
                "UPDATE underwriting_decisions
                 SET lifecycle_state = ?1, superseded_by_decision_id = ?2
                 WHERE decision_id = ?3",
                params![
                    underwriting_lifecycle_state_label(
                        UnderwritingDecisionLifecycleState::Superseded,
                    ),
                    artifact.decision_id,
                    supersedes_decision_id,
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn create_underwriting_appeal(
        &mut self,
        request: &UnderwritingAppealCreateRequest,
    ) -> Result<UnderwritingAppealRecord, ReceiptStoreError> {
        let tx = self.connection.transaction()?;
        let exists = tx
            .query_row(
                "SELECT decision_id FROM underwriting_decisions WHERE decision_id = ?1",
                params![request.decision_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if exists.is_none() {
            return Err(ReceiptStoreError::NotFound(format!(
                "underwriting decision `{}` not found",
                request.decision_id
            )));
        }
        let open_appeal = tx
            .query_row(
                "SELECT appeal_id FROM underwriting_appeals
                 WHERE decision_id = ?1 AND status = ?2",
                params![
                    request.decision_id,
                    underwriting_appeal_status_label(UnderwritingAppealStatus::Open)
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(appeal_id) = open_appeal {
            return Err(ReceiptStoreError::Conflict(format!(
                "underwriting decision `{}` already has open appeal `{appeal_id}`",
                request.decision_id
            )));
        }

        let created_at = unix_now();
        let appeal_id = format!(
            "uwa-{}",
            arc_core::sha256_hex(
                &canonical_json_bytes(&(
                    &request.decision_id,
                    &request.requested_by,
                    &request.reason,
                    &request.note,
                    created_at,
                ))
                .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
            )
        );
        let record = UnderwritingAppealRecord {
            schema: arc_kernel::UNDERWRITING_APPEAL_SCHEMA.to_string(),
            appeal_id: appeal_id.clone(),
            decision_id: request.decision_id.clone(),
            requested_by: request.requested_by.clone(),
            reason: request.reason.clone(),
            status: UnderwritingAppealStatus::Open,
            created_at,
            updated_at: created_at,
            note: request.note.clone(),
            resolved_by: None,
            replacement_decision_id: None,
        };
        tx.execute(
            "INSERT INTO underwriting_appeals (
                appeal_id, decision_id, requested_by, reason, status, note,
                created_at, updated_at, resolved_by, replacement_decision_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL)",
            params![
                record.appeal_id,
                record.decision_id,
                record.requested_by,
                record.reason,
                underwriting_appeal_status_label(record.status),
                record.note.as_deref(),
                record.created_at as i64,
                record.updated_at as i64,
            ],
        )?;
        tx.commit()?;
        Ok(record)
    }

    pub fn resolve_underwriting_appeal(
        &mut self,
        request: &UnderwritingAppealResolveRequest,
    ) -> Result<UnderwritingAppealRecord, ReceiptStoreError> {
        let tx = self.connection.transaction()?;
        let mut record = query_underwriting_appeal(&tx, &request.appeal_id)?.ok_or_else(|| {
            ReceiptStoreError::NotFound(format!(
                "underwriting appeal `{}` not found",
                request.appeal_id
            ))
        })?;
        if record.status != UnderwritingAppealStatus::Open {
            return Err(ReceiptStoreError::Conflict(format!(
                "underwriting appeal `{}` is already resolved",
                request.appeal_id
            )));
        }

        if let Some(replacement_decision_id) = request.replacement_decision_id.as_deref() {
            if request.resolution != UnderwritingAppealResolution::Accepted {
                return Err(ReceiptStoreError::Conflict(
                    "replacement underwriting decision may only be linked when an appeal is accepted"
                        .to_string(),
                ));
            }
            let replacement = tx
                .query_row(
                    "SELECT supersedes_decision_id FROM underwriting_decisions WHERE decision_id = ?1",
                    params![replacement_decision_id],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()?
                .ok_or_else(|| {
                    ReceiptStoreError::NotFound(format!(
                        "replacement underwriting decision `{replacement_decision_id}` not found"
                    ))
                })?;
            if replacement.as_deref() != Some(record.decision_id.as_str()) {
                return Err(ReceiptStoreError::Conflict(format!(
                    "replacement underwriting decision `{replacement_decision_id}` does not supersede `{}`",
                    record.decision_id
                )));
            }
        }

        record.status = match request.resolution {
            UnderwritingAppealResolution::Accepted => UnderwritingAppealStatus::Accepted,
            UnderwritingAppealResolution::Rejected => UnderwritingAppealStatus::Rejected,
        };
        record.updated_at = unix_now();
        record.note = request.note.clone().or(record.note);
        record.resolved_by = Some(request.resolved_by.clone());
        record.replacement_decision_id = request.replacement_decision_id.clone();

        tx.execute(
            "UPDATE underwriting_appeals
             SET status = ?1, note = ?2, updated_at = ?3, resolved_by = ?4,
                 replacement_decision_id = ?5
             WHERE appeal_id = ?6",
            params![
                underwriting_appeal_status_label(record.status),
                record.note.as_deref(),
                record.updated_at as i64,
                record.resolved_by.as_deref(),
                record.replacement_decision_id.as_deref(),
                record.appeal_id,
            ],
        )?;
        tx.commit()?;
        Ok(record)
    }

    pub fn query_underwriting_decisions(
        &self,
        query: &UnderwritingDecisionQuery,
    ) -> Result<UnderwritingDecisionListReport, ReceiptStoreError> {
        let normalized = query.normalized();
        let appeals = self.load_underwriting_appeals_by_decision()?;
        let mut statement = self.connection.prepare(
            "SELECT raw_json, lifecycle_state
             FROM underwriting_decisions
             ORDER BY issued_at DESC, decision_id DESC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        let mut matching_decisions = 0_u64;
        let mut active_decisions = 0_u64;
        let mut superseded_decisions = 0_u64;
        let mut open_appeals = 0_u64;
        let mut accepted_appeals = 0_u64;
        let mut rejected_appeals = 0_u64;
        let mut total_quoted_premium_units = 0_u64;
        let mut total_quoted_premium_currency = None;
        let mut quoted_premium_totals_by_currency = BTreeMap::<String, u64>::new();
        let mut decisions = Vec::new();

        for row in rows {
            let (raw_json, lifecycle_state_raw) = row?;
            let decision: SignedUnderwritingDecision = serde_json::from_str(&raw_json)?;
            let lifecycle_state =
                parse_underwriting_lifecycle_state(&lifecycle_state_raw).map_err(|error| {
                    ReceiptStoreError::Conflict(format!(
                        "invalid underwriting decision lifecycle state `{lifecycle_state_raw}`: {error}"
                    ))
                })?;
            let decision_appeals = appeals
                .get(decision.body.decision_id.as_str())
                .cloned()
                .unwrap_or_default();
            let latest_appeal = decision_appeals.iter().max_by(|left, right| {
                left.updated_at
                    .cmp(&right.updated_at)
                    .then(left.appeal_id.cmp(&right.appeal_id))
            });
            if !underwriting_decision_matches_query(
                &decision,
                lifecycle_state,
                latest_appeal.map(|appeal| appeal.status),
                &normalized,
            ) {
                continue;
            }

            matching_decisions += 1;
            match lifecycle_state {
                UnderwritingDecisionLifecycleState::Active => active_decisions += 1,
                UnderwritingDecisionLifecycleState::Superseded => superseded_decisions += 1,
            }
            for appeal in &decision_appeals {
                match appeal.status {
                    UnderwritingAppealStatus::Open => open_appeals += 1,
                    UnderwritingAppealStatus::Accepted => accepted_appeals += 1,
                    UnderwritingAppealStatus::Rejected => rejected_appeals += 1,
                }
            }
            if let Some(quoted_amount) = decision.body.premium.quoted_amount.as_ref() {
                let total = quoted_premium_totals_by_currency
                    .entry(quoted_amount.currency.clone())
                    .or_insert(0);
                *total = total.saturating_add(quoted_amount.units);
            }

            if decisions.len() < normalized.limit_or_default() {
                let open_appeal_count = decision_appeals
                    .iter()
                    .filter(|appeal| appeal.status == UnderwritingAppealStatus::Open)
                    .count() as u64;
                decisions.push(UnderwritingDecisionRow {
                    decision,
                    lifecycle_state,
                    open_appeal_count,
                    latest_appeal_id: latest_appeal.map(|appeal| appeal.appeal_id.clone()),
                    latest_appeal_status: latest_appeal.map(|appeal| appeal.status),
                });
            }
        }

        if quoted_premium_totals_by_currency.len() == 1 {
            if let Some((currency, units)) = quoted_premium_totals_by_currency
                .iter()
                .next()
                .map(|(currency, units)| (currency.clone(), *units))
            {
                total_quoted_premium_units = units;
                total_quoted_premium_currency = Some(currency);
            }
        }

        Ok(UnderwritingDecisionListReport {
            generated_at: unix_now(),
            filters: normalized,
            summary: UnderwritingDecisionSummary {
                matching_decisions,
                returned_decisions: decisions.len() as u64,
                active_decisions,
                superseded_decisions,
                open_appeals,
                accepted_appeals,
                rejected_appeals,
                total_quoted_premium_units,
                total_quoted_premium_currency,
                quoted_premium_totals_by_currency,
            },
            decisions,
        })
    }

    pub fn record_credit_facility(
        &mut self,
        facility: &SignedCreditFacility,
    ) -> Result<(), ReceiptStoreError> {
        if !facility
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "credit facility signature verification failed".to_string(),
            ));
        }

        let artifact = &facility.body;
        let tx = self.connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT facility_id FROM credit_facilities WHERE facility_id = ?1",
                params![artifact.facility_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "credit facility `{}` already exists",
                artifact.facility_id
            )));
        }

        if let Some(supersedes_facility_id) = artifact.supersedes_facility_id.as_deref() {
            let state = tx
                .query_row(
                    "SELECT lifecycle_state, superseded_by_facility_id, expires_at
                     FROM credit_facilities
                     WHERE facility_id = ?1",
                    params![supersedes_facility_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .optional()?
                .ok_or_else(|| {
                    ReceiptStoreError::NotFound(format!(
                        "superseded credit facility `{supersedes_facility_id}` not found"
                    ))
                })?;
            if state.0
                != credit_facility_lifecycle_state_label(CreditFacilityLifecycleState::Active)
                || state.1.is_some()
                || state.2.max(0) as u64 <= unix_now()
            {
                return Err(ReceiptStoreError::Conflict(format!(
                    "credit facility `{supersedes_facility_id}` is not active"
                )));
            }
        }

        tx.execute(
            "INSERT INTO credit_facilities (
                facility_id, issued_at, expires_at, capability_id, subject_key, tool_server,
                tool_name, disposition, lifecycle_state, supersedes_facility_id,
                superseded_by_facility_id, raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, ?11, ?12, ?13)",
            params![
                artifact.facility_id,
                artifact.issued_at as i64,
                artifact.expires_at as i64,
                artifact.report.filters.capability_id.as_deref(),
                artifact.report.filters.agent_subject.as_deref(),
                artifact.report.filters.tool_server.as_deref(),
                artifact.report.filters.tool_name.as_deref(),
                credit_facility_disposition_label(artifact.report.disposition),
                credit_facility_lifecycle_state_label(artifact.lifecycle_state),
                artifact.supersedes_facility_id.as_deref(),
                serde_json::to_string(facility)?,
                facility.signer_key.to_hex(),
                facility.signature.to_hex(),
            ],
        )?;

        if let Some(supersedes_facility_id) = artifact.supersedes_facility_id.as_deref() {
            tx.execute(
                "UPDATE credit_facilities
                 SET lifecycle_state = ?1, superseded_by_facility_id = ?2
                 WHERE facility_id = ?3",
                params![
                    credit_facility_lifecycle_state_label(
                        CreditFacilityLifecycleState::Superseded,
                    ),
                    artifact.facility_id,
                    supersedes_facility_id,
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn query_credit_facilities(
        &self,
        query: &CreditFacilityListQuery,
    ) -> Result<CreditFacilityListReport, ReceiptStoreError> {
        let normalized = query.normalized();
        let now = unix_now();
        let mut statement = self.connection.prepare(
            "SELECT raw_json, lifecycle_state, superseded_by_facility_id
             FROM credit_facilities
             ORDER BY issued_at DESC, facility_id DESC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?;

        let mut matching_facilities = 0_u64;
        let mut active_facilities = 0_u64;
        let mut superseded_facilities = 0_u64;
        let mut denied_facilities = 0_u64;
        let mut expired_facilities = 0_u64;
        let mut granted_facilities = 0_u64;
        let mut manual_review_facilities = 0_u64;
        let mut facilities = Vec::new();

        for row in rows {
            let (raw_json, lifecycle_state_raw, superseded_by_facility_id) = row?;
            let facility: SignedCreditFacility = serde_json::from_str(&raw_json)?;
            let persisted_lifecycle = parse_credit_facility_lifecycle_state(&lifecycle_state_raw)
                .map_err(|error| {
                ReceiptStoreError::Conflict(format!(
                    "invalid credit facility lifecycle state `{lifecycle_state_raw}`: {error}"
                ))
            })?;
            let lifecycle_state =
                effective_credit_facility_lifecycle_state(&facility, persisted_lifecycle, now);
            if !credit_facility_matches_query(&facility, lifecycle_state, &normalized) {
                continue;
            }

            matching_facilities += 1;
            match lifecycle_state {
                CreditFacilityLifecycleState::Active => active_facilities += 1,
                CreditFacilityLifecycleState::Superseded => superseded_facilities += 1,
                CreditFacilityLifecycleState::Denied => denied_facilities += 1,
                CreditFacilityLifecycleState::Expired => expired_facilities += 1,
            }
            match facility.body.report.disposition {
                CreditFacilityDisposition::Grant => granted_facilities += 1,
                CreditFacilityDisposition::ManualReview => manual_review_facilities += 1,
                CreditFacilityDisposition::Deny => {}
            }

            if facilities.len() < normalized.limit_or_default() {
                facilities.push(CreditFacilityRow {
                    facility,
                    lifecycle_state,
                    superseded_by_facility_id,
                });
            }
        }

        Ok(CreditFacilityListReport {
            schema: CREDIT_FACILITY_LIST_REPORT_SCHEMA.to_string(),
            generated_at: unix_now(),
            query: normalized,
            summary: CreditFacilityListSummary {
                matching_facilities,
                returned_facilities: facilities.len() as u64,
                active_facilities,
                superseded_facilities,
                denied_facilities,
                expired_facilities,
                granted_facilities,
                manual_review_facilities,
            },
            facilities,
        })
    }

    pub fn record_credit_bond(&mut self, bond: &SignedCreditBond) -> Result<(), ReceiptStoreError> {
        if !bond
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "credit bond signature verification failed".to_string(),
            ));
        }

        let artifact = &bond.body;
        let tx = self.connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT bond_id FROM credit_bonds WHERE bond_id = ?1",
                params![artifact.bond_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "credit bond `{}` already exists",
                artifact.bond_id
            )));
        }

        if let Some(supersedes_bond_id) = artifact.supersedes_bond_id.as_deref() {
            let state = tx
                .query_row(
                    "SELECT lifecycle_state, superseded_by_bond_id, expires_at
                     FROM credit_bonds
                     WHERE bond_id = ?1",
                    params![supersedes_bond_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .optional()?
                .ok_or_else(|| {
                    ReceiptStoreError::NotFound(format!(
                        "superseded credit bond `{supersedes_bond_id}` not found"
                    ))
                })?;
            if state.0 != credit_bond_lifecycle_state_label(CreditBondLifecycleState::Active)
                || state.1.is_some()
                || state.2.max(0) as u64 <= unix_now()
            {
                return Err(ReceiptStoreError::Conflict(format!(
                    "credit bond `{supersedes_bond_id}` is not active"
                )));
            }
        }

        tx.execute(
            "INSERT INTO credit_bonds (
                bond_id, issued_at, expires_at, facility_id, capability_id, subject_key,
                tool_server, tool_name, disposition, lifecycle_state, supersedes_bond_id,
                superseded_by_bond_id, raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL, ?12, ?13, ?14)",
            params![
                artifact.bond_id,
                artifact.issued_at as i64,
                artifact.expires_at as i64,
                artifact.report.latest_facility_id.as_deref(),
                artifact.report.filters.capability_id.as_deref(),
                artifact.report.filters.agent_subject.as_deref(),
                artifact.report.filters.tool_server.as_deref(),
                artifact.report.filters.tool_name.as_deref(),
                credit_bond_disposition_label(artifact.report.disposition),
                credit_bond_lifecycle_state_label(artifact.lifecycle_state),
                artifact.supersedes_bond_id.as_deref(),
                serde_json::to_string(bond)?,
                bond.signer_key.to_hex(),
                bond.signature.to_hex(),
            ],
        )?;

        if let Some(supersedes_bond_id) = artifact.supersedes_bond_id.as_deref() {
            tx.execute(
                "UPDATE credit_bonds
                 SET lifecycle_state = ?1, superseded_by_bond_id = ?2
                 WHERE bond_id = ?3",
                params![
                    credit_bond_lifecycle_state_label(CreditBondLifecycleState::Superseded),
                    artifact.bond_id,
                    supersedes_bond_id,
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn query_credit_bonds(
        &self,
        query: &CreditBondListQuery,
    ) -> Result<CreditBondListReport, ReceiptStoreError> {
        let normalized = query.normalized();
        let now = unix_now();
        let mut statement = self.connection.prepare(
            "SELECT raw_json, lifecycle_state, superseded_by_bond_id
             FROM credit_bonds
             ORDER BY issued_at DESC, bond_id DESC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?;

        let mut matching_bonds = 0_u64;
        let mut active_bonds = 0_u64;
        let mut superseded_bonds = 0_u64;
        let mut released_bonds = 0_u64;
        let mut impaired_bonds = 0_u64;
        let mut expired_bonds = 0_u64;
        let mut locked_bonds = 0_u64;
        let mut held_bonds = 0_u64;
        let mut bonds = Vec::new();

        for row in rows {
            let (raw_json, lifecycle_state_raw, superseded_by_bond_id) = row?;
            let bond: SignedCreditBond = serde_json::from_str(&raw_json)?;
            let persisted_lifecycle = parse_credit_bond_lifecycle_state(&lifecycle_state_raw)
                .map_err(|error| {
                    ReceiptStoreError::Conflict(format!(
                        "invalid credit bond lifecycle state `{lifecycle_state_raw}`: {error}"
                    ))
                })?;
            let lifecycle_state =
                effective_credit_bond_lifecycle_state(&bond, persisted_lifecycle, now);
            if !credit_bond_matches_query(&bond, lifecycle_state, &normalized) {
                continue;
            }

            matching_bonds += 1;
            match lifecycle_state {
                CreditBondLifecycleState::Active => active_bonds += 1,
                CreditBondLifecycleState::Superseded => superseded_bonds += 1,
                CreditBondLifecycleState::Released => released_bonds += 1,
                CreditBondLifecycleState::Impaired => impaired_bonds += 1,
                CreditBondLifecycleState::Expired => expired_bonds += 1,
            }
            match bond.body.report.disposition {
                CreditBondDisposition::Lock => locked_bonds += 1,
                CreditBondDisposition::Hold => held_bonds += 1,
                CreditBondDisposition::Release | CreditBondDisposition::Impair => {}
            }

            if bonds.len() < normalized.limit_or_default() {
                bonds.push(CreditBondRow {
                    bond,
                    lifecycle_state,
                    superseded_by_bond_id,
                });
            }
        }

        Ok(CreditBondListReport {
            schema: CREDIT_BOND_LIST_REPORT_SCHEMA.to_string(),
            generated_at: unix_now(),
            query: normalized,
            summary: CreditBondListSummary {
                matching_bonds,
                returned_bonds: bonds.len() as u64,
                active_bonds,
                superseded_bonds,
                released_bonds,
                impaired_bonds,
                expired_bonds,
                locked_bonds,
                held_bonds,
            },
            bonds,
        })
    }

    pub fn record_liability_provider(
        &mut self,
        provider: &SignedLiabilityProvider,
    ) -> Result<(), ReceiptStoreError> {
        if !provider
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "liability provider signature verification failed".to_string(),
            ));
        }
        provider
            .body
            .report
            .validate()
            .map_err(ReceiptStoreError::Conflict)?;

        let artifact = &provider.body;
        let tx = self.connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT provider_record_id FROM liability_providers WHERE provider_record_id = ?1",
                params![artifact.provider_record_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability provider `{}` already exists",
                artifact.provider_record_id
            )));
        }

        if let Some(supersedes_provider_record_id) =
            artifact.supersedes_provider_record_id.as_deref()
        {
            let state = tx
                .query_row(
                    "SELECT raw_json, lifecycle_state, superseded_by_provider_record_id
                     FROM liability_providers
                     WHERE provider_record_id = ?1",
                    params![supersedes_provider_record_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Option<String>>(2)?,
                        ))
                    },
                )
                .optional()?
                .ok_or_else(|| {
                    ReceiptStoreError::NotFound(format!(
                        "superseded liability provider `{supersedes_provider_record_id}` not found"
                    ))
                })?;
            let persisted: SignedLiabilityProvider = serde_json::from_str(&state.0)?;
            if persisted.body.report.provider_id != artifact.report.provider_id {
                return Err(ReceiptStoreError::Conflict(format!(
                    "liability provider `{}` cannot supersede `{}` because provider_id differs",
                    artifact.provider_record_id, supersedes_provider_record_id
                )));
            }
            if state.1
                != liability_provider_lifecycle_state_label(LiabilityProviderLifecycleState::Active)
                || state.2.is_some()
            {
                return Err(ReceiptStoreError::Conflict(format!(
                    "liability provider `{supersedes_provider_record_id}` is not active"
                )));
            }
        }

        tx.execute(
            "INSERT INTO liability_providers (
                provider_record_id, issued_at, provider_id, lifecycle_state,
                supersedes_provider_record_id, superseded_by_provider_record_id, raw_json,
                signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, ?8)",
            params![
                artifact.provider_record_id,
                artifact.issued_at as i64,
                artifact.report.provider_id,
                liability_provider_lifecycle_state_label(artifact.lifecycle_state),
                artifact.supersedes_provider_record_id.as_deref(),
                serde_json::to_string(provider)?,
                provider.signer_key.to_hex(),
                provider.signature.to_hex(),
            ],
        )?;

        if let Some(supersedes_provider_record_id) =
            artifact.supersedes_provider_record_id.as_deref()
        {
            tx.execute(
                "UPDATE liability_providers
                 SET lifecycle_state = ?1, superseded_by_provider_record_id = ?2
                 WHERE provider_record_id = ?3",
                params![
                    liability_provider_lifecycle_state_label(
                        LiabilityProviderLifecycleState::Superseded,
                    ),
                    artifact.provider_record_id,
                    supersedes_provider_record_id,
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn query_liability_providers(
        &self,
        query: &LiabilityProviderListQuery,
    ) -> Result<LiabilityProviderListReport, ReceiptStoreError> {
        let normalized = query.normalized();
        let mut statement = self.connection.prepare(
            "SELECT raw_json, lifecycle_state, superseded_by_provider_record_id
             FROM liability_providers
             ORDER BY issued_at DESC, provider_record_id DESC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?;

        let mut matching_providers = 0_u64;
        let mut active_providers = 0_u64;
        let mut suspended_providers = 0_u64;
        let mut superseded_providers = 0_u64;
        let mut retired_providers = 0_u64;
        let mut providers = Vec::new();

        for row in rows {
            let (raw_json, lifecycle_state_raw, superseded_by_provider_record_id) = row?;
            let provider: SignedLiabilityProvider = serde_json::from_str(&raw_json)?;
            let lifecycle_state =
                parse_liability_provider_lifecycle_state(&lifecycle_state_raw).map_err(|error| {
                    ReceiptStoreError::Conflict(format!(
                        "invalid liability provider lifecycle state `{lifecycle_state_raw}`: {error}"
                    ))
                })?;
            if !liability_provider_matches_query(&provider, lifecycle_state, &normalized) {
                continue;
            }

            matching_providers += 1;
            match lifecycle_state {
                LiabilityProviderLifecycleState::Active => active_providers += 1,
                LiabilityProviderLifecycleState::Suspended => suspended_providers += 1,
                LiabilityProviderLifecycleState::Superseded => superseded_providers += 1,
                LiabilityProviderLifecycleState::Retired => retired_providers += 1,
            }

            if providers.len() < normalized.limit_or_default() {
                providers.push(LiabilityProviderRow {
                    provider,
                    lifecycle_state,
                    superseded_by_provider_record_id,
                });
            }
        }

        Ok(LiabilityProviderListReport {
            schema: LIABILITY_PROVIDER_LIST_REPORT_SCHEMA.to_string(),
            generated_at: unix_now(),
            query: normalized,
            summary: LiabilityProviderListSummary {
                matching_providers,
                returned_providers: providers.len() as u64,
                active_providers,
                suspended_providers,
                superseded_providers,
                retired_providers,
            },
            providers,
        })
    }

    pub fn resolve_liability_provider(
        &self,
        query: &LiabilityProviderResolutionQuery,
    ) -> Result<LiabilityProviderResolutionReport, ReceiptStoreError> {
        query.validate().map_err(ReceiptStoreError::Conflict)?;
        let normalized = query.normalized();
        let mut statement = self.connection.prepare(
            "SELECT raw_json, lifecycle_state
             FROM liability_providers
             WHERE provider_id = ?1
             ORDER BY issued_at DESC, provider_record_id DESC",
        )?;
        let rows = statement.query_map(params![normalized.provider_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        let mut active_provider = None;
        let mut saw_provider = false;
        for row in rows {
            let (raw_json, lifecycle_state_raw) = row?;
            saw_provider = true;
            let provider: SignedLiabilityProvider = serde_json::from_str(&raw_json)?;
            let lifecycle_state =
                parse_liability_provider_lifecycle_state(&lifecycle_state_raw).map_err(|error| {
                    ReceiptStoreError::Conflict(format!(
                        "invalid liability provider lifecycle state `{lifecycle_state_raw}`: {error}"
                    ))
                })?;
            if lifecycle_state == LiabilityProviderLifecycleState::Active {
                active_provider = Some(provider);
                break;
            }
        }

        let provider = active_provider.ok_or_else(|| {
            if saw_provider {
                ReceiptStoreError::Conflict(format!(
                    "liability provider `{}` has no active registry entry",
                    normalized.provider_id
                ))
            } else {
                ReceiptStoreError::NotFound(format!(
                    "liability provider `{}` not found",
                    normalized.provider_id
                ))
            }
        })?;

        let matched_policy = provider
            .body
            .report
            .policies
            .iter()
            .find(|policy| liability_provider_policy_matches_resolution(policy, &normalized))
            .cloned()
            .ok_or_else(|| {
                ReceiptStoreError::Conflict(format!(
                    "liability provider `{}` does not support jurisdiction `{}`, coverage `{}` in currency `{}`",
                    normalized.provider_id,
                    normalized.jurisdiction,
                    serde_json::to_string(&normalized.coverage_class)
                        .unwrap_or_else(|_| "\"unknown\"".to_string()),
                    normalized.currency,
                ))
            })?;

        Ok(LiabilityProviderResolutionReport {
            schema: LIABILITY_PROVIDER_RESOLUTION_REPORT_SCHEMA.to_string(),
            generated_at: unix_now(),
            query: normalized,
            provider: provider.clone(),
            matched_policy,
            support_boundary: provider.body.report.support_boundary.clone(),
        })
    }

    pub fn record_liability_quote_request(
        &mut self,
        request: &SignedLiabilityQuoteRequest,
    ) -> Result<(), ReceiptStoreError> {
        if !request
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "liability quote request signature verification failed".to_string(),
            ));
        }
        request
            .body
            .validate()
            .map_err(ReceiptStoreError::Conflict)?;

        let artifact = &request.body;
        let tx = self.connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT quote_request_id FROM liability_quote_requests WHERE quote_request_id = ?1",
                params![artifact.quote_request_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability quote request `{}` already exists",
                artifact.quote_request_id
            )));
        }

        let (provider_raw_json, lifecycle_state_raw) = tx
            .query_row(
                "SELECT raw_json, lifecycle_state
                 FROM liability_providers
                 WHERE provider_record_id = ?1",
                params![artifact.provider_policy.provider_record_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "liability provider `{}` not found",
                    artifact.provider_policy.provider_record_id
                ))
            })?;
        let provider: SignedLiabilityProvider = serde_json::from_str(&provider_raw_json)?;
        let lifecycle_state = parse_liability_provider_lifecycle_state(&lifecycle_state_raw)?;
        if lifecycle_state != LiabilityProviderLifecycleState::Active {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability provider `{}` is not active",
                artifact.provider_policy.provider_record_id
            )));
        }
        if provider.body.report.provider_id != artifact.provider_policy.provider_id {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability quote request provider `{}` does not match active provider `{}`",
                artifact.provider_policy.provider_id, provider.body.report.provider_id
            )));
        }
        let policy_supported = provider.body.report.policies.iter().any(|policy| {
            policy
                .jurisdiction
                .eq_ignore_ascii_case(&artifact.provider_policy.jurisdiction)
                && policy
                    .coverage_classes
                    .contains(&artifact.provider_policy.coverage_class)
                && policy.supported_currencies.iter().any(|currency| {
                    currency.eq_ignore_ascii_case(&artifact.provider_policy.currency)
                })
        });
        if !policy_supported {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability provider `{}` does not support jurisdiction `{}`, coverage, and currency requested by quote request",
                artifact.provider_policy.provider_id, artifact.provider_policy.jurisdiction
            )));
        }

        tx.execute(
            "INSERT INTO liability_quote_requests (
                quote_request_id, issued_at, provider_id, jurisdiction, coverage_class,
                currency, subject_key, raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                artifact.quote_request_id,
                artifact.issued_at as i64,
                artifact.provider_policy.provider_id,
                artifact.provider_policy.jurisdiction,
                serde_json::to_string(&artifact.provider_policy.coverage_class)?,
                artifact.provider_policy.currency,
                artifact.risk_package.body.subject_key,
                serde_json::to_string(request)?,
                request.signer_key.to_hex(),
                request.signature.to_hex(),
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn record_liability_quote_response(
        &mut self,
        response: &SignedLiabilityQuoteResponse,
    ) -> Result<(), ReceiptStoreError> {
        if !response
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "liability quote response signature verification failed".to_string(),
            ));
        }
        response
            .body
            .validate()
            .map_err(ReceiptStoreError::Conflict)?;

        let artifact = &response.body;
        let tx = self.connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT quote_response_id FROM liability_quote_responses WHERE quote_response_id = ?1",
                params![artifact.quote_response_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability quote response `{}` already exists",
                artifact.quote_response_id
            )));
        }

        let stored_request_raw_json = tx
            .query_row(
                "SELECT raw_json
                 FROM liability_quote_requests
                 WHERE quote_request_id = ?1",
                params![artifact.quote_request.body.quote_request_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "liability quote request `{}` not found",
                    artifact.quote_request.body.quote_request_id
                ))
            })?;
        let stored_request: SignedLiabilityQuoteRequest =
            serde_json::from_str(&stored_request_raw_json)?;
        if stored_request.body != artifact.quote_request.body {
            return Err(ReceiptStoreError::Conflict(
                "liability quote response quote_request does not match the persisted request"
                    .to_string(),
            ));
        }

        if let Some(supersedes_quote_response_id) = artifact.supersedes_quote_response_id.as_deref()
        {
            let state = tx
                .query_row(
                    "SELECT raw_json, superseded_by_quote_response_id
                     FROM liability_quote_responses
                     WHERE quote_response_id = ?1",
                    params![supersedes_quote_response_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
                )
                .optional()?
                .ok_or_else(|| {
                    ReceiptStoreError::NotFound(format!(
                        "superseded liability quote response `{supersedes_quote_response_id}` not found"
                    ))
                })?;
            let prior: SignedLiabilityQuoteResponse = serde_json::from_str(&state.0)?;
            if prior.body.quote_request.body.quote_request_id
                != artifact.quote_request.body.quote_request_id
            {
                return Err(ReceiptStoreError::Conflict(format!(
                    "liability quote response `{}` cannot supersede `{}` because quote_request_id differs",
                    artifact.quote_response_id, supersedes_quote_response_id
                )));
            }
            if state.1.is_some() {
                return Err(ReceiptStoreError::Conflict(format!(
                    "liability quote response `{supersedes_quote_response_id}` is already superseded"
                )));
            }
        } else {
            let active_response = tx
                .query_row(
                    "SELECT quote_response_id
                     FROM liability_quote_responses
                     WHERE quote_request_id = ?1 AND superseded_by_quote_response_id IS NULL",
                    params![artifact.quote_request.body.quote_request_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if let Some(active_response) = active_response {
                return Err(ReceiptStoreError::Conflict(format!(
                    "liability quote request `{}` already has active response `{active_response}`",
                    artifact.quote_request.body.quote_request_id
                )));
            }
        }

        let expires_at = artifact
            .quoted_terms
            .as_ref()
            .map(|terms| terms.expires_at as i64);
        tx.execute(
            "INSERT INTO liability_quote_responses (
                quote_response_id, issued_at, quote_request_id, provider_id, disposition,
                expires_at, supersedes_quote_response_id, superseded_by_quote_response_id,
                raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8, ?9, ?10)",
            params![
                artifact.quote_response_id,
                artifact.issued_at as i64,
                artifact.quote_request.body.quote_request_id,
                artifact.quote_request.body.provider_policy.provider_id,
                liability_quote_disposition_label(&artifact.disposition),
                expires_at,
                artifact.supersedes_quote_response_id.as_deref(),
                serde_json::to_string(response)?,
                response.signer_key.to_hex(),
                response.signature.to_hex(),
            ],
        )?;

        if let Some(supersedes_quote_response_id) = artifact.supersedes_quote_response_id.as_deref()
        {
            tx.execute(
                "UPDATE liability_quote_responses
                 SET superseded_by_quote_response_id = ?1
                 WHERE quote_response_id = ?2",
                params![artifact.quote_response_id, supersedes_quote_response_id],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn record_liability_placement(
        &mut self,
        placement: &SignedLiabilityPlacement,
    ) -> Result<(), ReceiptStoreError> {
        if !placement
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "liability placement signature verification failed".to_string(),
            ));
        }
        placement
            .body
            .validate()
            .map_err(ReceiptStoreError::Conflict)?;

        let artifact = &placement.body;
        let tx = self.connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT placement_id FROM liability_placements WHERE placement_id = ?1",
                params![artifact.placement_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability placement `{}` already exists",
                artifact.placement_id
            )));
        }

        let stored_request_raw_json = tx
            .query_row(
                "SELECT raw_json
                 FROM liability_quote_requests
                 WHERE quote_request_id = ?1",
                params![
                    artifact
                        .quote_response
                        .body
                        .quote_request
                        .body
                        .quote_request_id
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "liability quote request `{}` not found",
                    artifact
                        .quote_response
                        .body
                        .quote_request
                        .body
                        .quote_request_id
                ))
            })?;
        let stored_request: SignedLiabilityQuoteRequest =
            serde_json::from_str(&stored_request_raw_json)?;
        if stored_request.body != artifact.quote_response.body.quote_request.body {
            return Err(ReceiptStoreError::Conflict(
                "liability placement quote_request does not match the persisted request"
                    .to_string(),
            ));
        }

        let (stored_response_raw_json, superseded_by_quote_response_id) = tx
            .query_row(
                "SELECT raw_json, superseded_by_quote_response_id
                 FROM liability_quote_responses
                 WHERE quote_response_id = ?1",
                params![artifact.quote_response.body.quote_response_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "liability quote response `{}` not found",
                    artifact.quote_response.body.quote_response_id
                ))
            })?;
        if superseded_by_quote_response_id.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability quote response `{}` is superseded",
                artifact.quote_response.body.quote_response_id
            )));
        }
        let stored_response: SignedLiabilityQuoteResponse =
            serde_json::from_str(&stored_response_raw_json)?;
        if stored_response.body != artifact.quote_response.body {
            return Err(ReceiptStoreError::Conflict(
                "liability placement quote_response does not match the persisted response"
                    .to_string(),
            ));
        }

        let existing_request_placement = tx
            .query_row(
                "SELECT placement_id
                 FROM liability_placements
                 WHERE quote_request_id = ?1",
                params![
                    artifact
                        .quote_response
                        .body
                        .quote_request
                        .body
                        .quote_request_id
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(existing_request_placement) = existing_request_placement {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability quote request `{}` already has placement `{existing_request_placement}`",
                artifact
                    .quote_response
                    .body
                    .quote_request
                    .body
                    .quote_request_id
            )));
        }

        tx.execute(
            "INSERT INTO liability_placements (
                placement_id, issued_at, quote_request_id, quote_response_id, provider_id,
                raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                artifact.placement_id,
                artifact.issued_at as i64,
                artifact
                    .quote_response
                    .body
                    .quote_request
                    .body
                    .quote_request_id,
                artifact.quote_response.body.quote_response_id,
                artifact
                    .quote_response
                    .body
                    .quote_request
                    .body
                    .provider_policy
                    .provider_id,
                serde_json::to_string(placement)?,
                placement.signer_key.to_hex(),
                placement.signature.to_hex(),
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn record_liability_bound_coverage(
        &mut self,
        coverage: &SignedLiabilityBoundCoverage,
    ) -> Result<(), ReceiptStoreError> {
        if !coverage
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "liability bound coverage signature verification failed".to_string(),
            ));
        }
        coverage
            .body
            .validate()
            .map_err(ReceiptStoreError::Conflict)?;

        let artifact = &coverage.body;
        let tx = self.connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT bound_coverage_id FROM liability_bound_coverages WHERE bound_coverage_id = ?1",
                params![artifact.bound_coverage_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability bound coverage `{}` already exists",
                artifact.bound_coverage_id
            )));
        }

        let stored_placement_raw_json = tx
            .query_row(
                "SELECT raw_json
                 FROM liability_placements
                 WHERE placement_id = ?1",
                params![artifact.placement.body.placement_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "liability placement `{}` not found",
                    artifact.placement.body.placement_id
                ))
            })?;
        let stored_placement: SignedLiabilityPlacement =
            serde_json::from_str(&stored_placement_raw_json)?;
        if stored_placement.body != artifact.placement.body {
            return Err(ReceiptStoreError::Conflict(
                "liability bound coverage placement does not match the persisted placement"
                    .to_string(),
            ));
        }

        let existing_bound = tx
            .query_row(
                "SELECT bound_coverage_id
                 FROM liability_bound_coverages
                 WHERE placement_id = ?1",
                params![artifact.placement.body.placement_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(existing_bound) = existing_bound {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability placement `{}` already has bound coverage `{existing_bound}`",
                artifact.placement.body.placement_id
            )));
        }

        tx.execute(
            "INSERT INTO liability_bound_coverages (
                bound_coverage_id, issued_at, quote_request_id, quote_response_id, placement_id,
                provider_id, raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                artifact.bound_coverage_id,
                artifact.issued_at as i64,
                artifact
                    .placement
                    .body
                    .quote_response
                    .body
                    .quote_request
                    .body
                    .quote_request_id,
                artifact
                    .placement
                    .body
                    .quote_response
                    .body
                    .quote_response_id,
                artifact.placement.body.placement_id,
                artifact
                    .placement
                    .body
                    .quote_response
                    .body
                    .quote_request
                    .body
                    .provider_policy
                    .provider_id,
                serde_json::to_string(coverage)?,
                coverage.signer_key.to_hex(),
                coverage.signature.to_hex(),
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn query_liability_market_workflows(
        &self,
        query: &LiabilityMarketWorkflowQuery,
    ) -> Result<LiabilityMarketWorkflowReport, ReceiptStoreError> {
        let normalized = query.normalized();
        let mut statement = self.connection.prepare(
            "SELECT raw_json
             FROM liability_quote_requests
             ORDER BY issued_at DESC, quote_request_id DESC",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;

        let mut matching_requests = 0_u64;
        let mut quote_responses = 0_u64;
        let mut quoted_responses = 0_u64;
        let mut declined_responses = 0_u64;
        let mut placements = 0_u64;
        let mut bound_coverages = 0_u64;
        let mut workflows = Vec::new();

        for row in rows {
            let raw_json = row?;
            let quote_request: SignedLiabilityQuoteRequest = serde_json::from_str(&raw_json)?;
            if !liability_market_workflow_matches_query(&quote_request, &normalized) {
                continue;
            }
            matching_requests += 1;

            let latest_quote_response = self
                .connection
                .query_row(
                    "SELECT raw_json
                     FROM liability_quote_responses
                     WHERE quote_request_id = ?1 AND superseded_by_quote_response_id IS NULL
                     ORDER BY issued_at DESC, quote_response_id DESC
                     LIMIT 1",
                    params![quote_request.body.quote_request_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .map(|raw_json| serde_json::from_str::<SignedLiabilityQuoteResponse>(&raw_json))
                .transpose()?;
            if let Some(response) = latest_quote_response.as_ref() {
                quote_responses += 1;
                match response.body.disposition {
                    LiabilityQuoteDisposition::Quoted => quoted_responses += 1,
                    LiabilityQuoteDisposition::Declined => declined_responses += 1,
                }
            }

            let placement = self
                .connection
                .query_row(
                    "SELECT raw_json
                     FROM liability_placements
                     WHERE quote_request_id = ?1
                     ORDER BY issued_at DESC, placement_id DESC
                     LIMIT 1",
                    params![quote_request.body.quote_request_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .map(|raw_json| serde_json::from_str::<SignedLiabilityPlacement>(&raw_json))
                .transpose()?;
            if placement.is_some() {
                placements += 1;
            }

            let bound_coverage = self
                .connection
                .query_row(
                    "SELECT raw_json
                     FROM liability_bound_coverages
                     WHERE quote_request_id = ?1
                     ORDER BY issued_at DESC, bound_coverage_id DESC
                     LIMIT 1",
                    params![quote_request.body.quote_request_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .map(|raw_json| serde_json::from_str::<SignedLiabilityBoundCoverage>(&raw_json))
                .transpose()?;
            if bound_coverage.is_some() {
                bound_coverages += 1;
            }

            if workflows.len() < normalized.limit_or_default() {
                workflows.push(LiabilityMarketWorkflowRow {
                    quote_request,
                    latest_quote_response,
                    placement,
                    bound_coverage,
                });
            }
        }

        Ok(LiabilityMarketWorkflowReport {
            schema: LIABILITY_MARKET_WORKFLOW_REPORT_SCHEMA.to_string(),
            generated_at: unix_now(),
            query: normalized,
            summary: LiabilityMarketWorkflowSummary {
                matching_requests,
                returned_requests: workflows.len() as u64,
                quote_responses,
                quoted_responses,
                declined_responses,
                placements,
                bound_coverages,
            },
            workflows,
        })
    }

    pub fn record_liability_claim_package(
        &mut self,
        claim: &SignedLiabilityClaimPackage,
    ) -> Result<(), ReceiptStoreError> {
        if !claim
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "liability claim package signature verification failed".to_string(),
            ));
        }
        claim.body.validate().map_err(ReceiptStoreError::Conflict)?;

        let artifact = &claim.body;
        let tx = self.connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT claim_id FROM liability_claim_packages WHERE claim_id = ?1",
                params![artifact.claim_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability claim package `{}` already exists",
                artifact.claim_id
            )));
        }

        let stored_bound_raw_json = tx
            .query_row(
                "SELECT raw_json
                 FROM liability_bound_coverages
                 WHERE bound_coverage_id = ?1",
                params![artifact.bound_coverage.body.bound_coverage_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "liability bound coverage `{}` not found",
                    artifact.bound_coverage.body.bound_coverage_id
                ))
            })?;
        let stored_bound: SignedLiabilityBoundCoverage =
            serde_json::from_str(&stored_bound_raw_json)?;
        if stored_bound.body != artifact.bound_coverage.body {
            return Err(ReceiptStoreError::Conflict(
                "liability claim package bound_coverage does not match the persisted bound coverage"
                    .to_string(),
            ));
        }

        let stored_bond_raw_json = tx
            .query_row(
                "SELECT raw_json
                 FROM credit_bonds
                 WHERE bond_id = ?1",
                params![artifact.bond.body.bond_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "credit bond `{}` not found",
                    artifact.bond.body.bond_id
                ))
            })?;
        let stored_bond: SignedCreditBond = serde_json::from_str(&stored_bond_raw_json)?;
        if stored_bond.body != artifact.bond.body {
            return Err(ReceiptStoreError::Conflict(
                "liability claim package bond does not match the persisted credit bond".to_string(),
            ));
        }

        let stored_loss_raw_json = tx
            .query_row(
                "SELECT raw_json
                 FROM credit_loss_lifecycle
                 WHERE event_id = ?1",
                params![artifact.loss_event.body.event_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "credit loss lifecycle event `{}` not found",
                    artifact.loss_event.body.event_id
                ))
            })?;
        let stored_loss: SignedCreditLossLifecycle = serde_json::from_str(&stored_loss_raw_json)?;
        if stored_loss.body != artifact.loss_event.body {
            return Err(ReceiptStoreError::Conflict(
                "liability claim package loss_event does not match the persisted credit loss lifecycle event"
                    .to_string(),
            ));
        }

        for receipt_id in &artifact.receipt_ids {
            let exists = tx
                .query_row(
                    "SELECT 1 FROM arc_tool_receipts WHERE receipt_id = ?1",
                    params![receipt_id],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?;
            if exists.is_none() {
                return Err(ReceiptStoreError::NotFound(format!(
                    "receipt {receipt_id} does not exist"
                )));
            }
        }

        tx.execute(
            "INSERT INTO liability_claim_packages (
                claim_id, issued_at, provider_id, policy_number, jurisdiction, subject_key,
                claim_event_at, raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                artifact.claim_id,
                artifact.issued_at as i64,
                artifact
                    .bound_coverage
                    .body
                    .placement
                    .body
                    .quote_response
                    .body
                    .quote_request
                    .body
                    .provider_policy
                    .provider_id,
                artifact.bound_coverage.body.policy_number,
                artifact
                    .bound_coverage
                    .body
                    .placement
                    .body
                    .quote_response
                    .body
                    .quote_request
                    .body
                    .provider_policy
                    .jurisdiction,
                artifact
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
                    .subject_key,
                artifact.claim_event_at as i64,
                serde_json::to_string(claim)?,
                claim.signer_key.to_hex(),
                claim.signature.to_hex(),
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn record_liability_claim_response(
        &mut self,
        response: &SignedLiabilityClaimResponse,
    ) -> Result<(), ReceiptStoreError> {
        if !response
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "liability claim response signature verification failed".to_string(),
            ));
        }
        response
            .body
            .validate()
            .map_err(ReceiptStoreError::Conflict)?;

        let artifact = &response.body;
        let tx = self.connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT claim_response_id
                 FROM liability_claim_responses
                 WHERE claim_response_id = ?1",
                params![artifact.claim_response_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability claim response `{}` already exists",
                artifact.claim_response_id
            )));
        }

        let stored_claim_raw_json = tx
            .query_row(
                "SELECT raw_json
                 FROM liability_claim_packages
                 WHERE claim_id = ?1",
                params![artifact.claim.body.claim_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "liability claim package `{}` not found",
                    artifact.claim.body.claim_id
                ))
            })?;
        let stored_claim: SignedLiabilityClaimPackage =
            serde_json::from_str(&stored_claim_raw_json)?;
        if stored_claim.body != artifact.claim.body {
            return Err(ReceiptStoreError::Conflict(
                "liability claim response claim does not match the persisted claim package"
                    .to_string(),
            ));
        }

        tx.execute(
            "INSERT INTO liability_claim_responses (
                claim_response_id, issued_at, claim_id, provider_id, disposition,
                raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                artifact.claim_response_id,
                artifact.issued_at as i64,
                artifact.claim.body.claim_id,
                artifact
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
                    .provider_policy
                    .provider_id,
                serde_json::to_string(&artifact.disposition)?,
                serde_json::to_string(response)?,
                response.signer_key.to_hex(),
                response.signature.to_hex(),
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn record_liability_claim_dispute(
        &mut self,
        dispute: &SignedLiabilityClaimDispute,
    ) -> Result<(), ReceiptStoreError> {
        if !dispute
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "liability claim dispute signature verification failed".to_string(),
            ));
        }
        dispute
            .body
            .validate()
            .map_err(ReceiptStoreError::Conflict)?;

        let artifact = &dispute.body;
        let tx = self.connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT dispute_id FROM liability_claim_disputes WHERE dispute_id = ?1",
                params![artifact.dispute_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability claim dispute `{}` already exists",
                artifact.dispute_id
            )));
        }

        let stored_response_raw_json = tx
            .query_row(
                "SELECT raw_json
                 FROM liability_claim_responses
                 WHERE claim_response_id = ?1",
                params![artifact.provider_response.body.claim_response_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "liability claim response `{}` not found",
                    artifact.provider_response.body.claim_response_id
                ))
            })?;
        let stored_response: SignedLiabilityClaimResponse =
            serde_json::from_str(&stored_response_raw_json)?;
        if stored_response.body != artifact.provider_response.body {
            return Err(ReceiptStoreError::Conflict(
                "liability claim dispute provider_response does not match the persisted claim response"
                    .to_string(),
            ));
        }

        tx.execute(
            "INSERT INTO liability_claim_disputes (
                dispute_id, issued_at, claim_id, claim_response_id, provider_id,
                raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                artifact.dispute_id,
                artifact.issued_at as i64,
                artifact.provider_response.body.claim.body.claim_id,
                artifact.provider_response.body.claim_response_id,
                artifact
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
                    .provider_policy
                    .provider_id,
                serde_json::to_string(dispute)?,
                dispute.signer_key.to_hex(),
                dispute.signature.to_hex(),
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn record_liability_claim_adjudication(
        &mut self,
        adjudication: &SignedLiabilityClaimAdjudication,
    ) -> Result<(), ReceiptStoreError> {
        if !adjudication
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "liability claim adjudication signature verification failed".to_string(),
            ));
        }
        adjudication
            .body
            .validate()
            .map_err(ReceiptStoreError::Conflict)?;

        let artifact = &adjudication.body;
        let tx = self.connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT adjudication_id
                 FROM liability_claim_adjudications
                 WHERE adjudication_id = ?1",
                params![artifact.adjudication_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "liability claim adjudication `{}` already exists",
                artifact.adjudication_id
            )));
        }

        let stored_dispute_raw_json = tx
            .query_row(
                "SELECT raw_json
                 FROM liability_claim_disputes
                 WHERE dispute_id = ?1",
                params![artifact.dispute.body.dispute_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "liability claim dispute `{}` not found",
                    artifact.dispute.body.dispute_id
                ))
            })?;
        let stored_dispute: SignedLiabilityClaimDispute =
            serde_json::from_str(&stored_dispute_raw_json)?;
        if stored_dispute.body != artifact.dispute.body {
            return Err(ReceiptStoreError::Conflict(
                "liability claim adjudication dispute does not match the persisted claim dispute"
                    .to_string(),
            ));
        }

        tx.execute(
            "INSERT INTO liability_claim_adjudications (
                adjudication_id, issued_at, claim_id, dispute_id, outcome,
                raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                artifact.adjudication_id,
                artifact.issued_at as i64,
                artifact
                    .dispute
                    .body
                    .provider_response
                    .body
                    .claim
                    .body
                    .claim_id,
                artifact.dispute.body.dispute_id,
                serde_json::to_string(&artifact.outcome)?,
                serde_json::to_string(adjudication)?,
                adjudication.signer_key.to_hex(),
                adjudication.signature.to_hex(),
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn query_liability_claim_workflows(
        &self,
        query: &LiabilityClaimWorkflowQuery,
    ) -> Result<LiabilityClaimWorkflowReport, ReceiptStoreError> {
        let normalized = query.normalized();
        let mut statement = self.connection.prepare(
            "SELECT raw_json
             FROM liability_claim_packages
             ORDER BY issued_at DESC, claim_id DESC",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;

        let mut matching_claims = 0_u64;
        let mut provider_responses = 0_u64;
        let mut accepted_responses = 0_u64;
        let mut denied_responses = 0_u64;
        let mut disputes = 0_u64;
        let mut adjudications = 0_u64;
        let mut claims = Vec::new();

        for row in rows {
            let raw_json = row?;
            let claim: SignedLiabilityClaimPackage = serde_json::from_str(&raw_json)?;
            if !liability_claim_workflow_matches_query(&claim, &normalized) {
                continue;
            }
            matching_claims += 1;

            let provider_response = self
                .connection
                .query_row(
                    "SELECT raw_json
                     FROM liability_claim_responses
                     WHERE claim_id = ?1
                     ORDER BY issued_at DESC, claim_response_id DESC
                     LIMIT 1",
                    params![claim.body.claim_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .map(|raw_json| serde_json::from_str::<SignedLiabilityClaimResponse>(&raw_json))
                .transpose()?;
            if let Some(response) = provider_response.as_ref() {
                provider_responses += 1;
                match response.body.disposition {
                    LiabilityClaimResponseDisposition::Accepted => accepted_responses += 1,
                    LiabilityClaimResponseDisposition::Denied => denied_responses += 1,
                    LiabilityClaimResponseDisposition::Acknowledged => {}
                }
            }

            let dispute = self
                .connection
                .query_row(
                    "SELECT raw_json
                     FROM liability_claim_disputes
                     WHERE claim_id = ?1
                     ORDER BY issued_at DESC, dispute_id DESC
                     LIMIT 1",
                    params![claim.body.claim_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .map(|raw_json| serde_json::from_str::<SignedLiabilityClaimDispute>(&raw_json))
                .transpose()?;
            if dispute.is_some() {
                disputes += 1;
            }

            let adjudication = self
                .connection
                .query_row(
                    "SELECT raw_json
                     FROM liability_claim_adjudications
                     WHERE claim_id = ?1
                     ORDER BY issued_at DESC, adjudication_id DESC
                     LIMIT 1",
                    params![claim.body.claim_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .map(|raw_json| serde_json::from_str::<SignedLiabilityClaimAdjudication>(&raw_json))
                .transpose()?;
            if adjudication.is_some() {
                adjudications += 1;
            }

            if claims.len() < normalized.limit_or_default() {
                claims.push(LiabilityClaimWorkflowRow {
                    claim,
                    provider_response,
                    dispute,
                    adjudication,
                });
            }
        }

        Ok(LiabilityClaimWorkflowReport {
            schema: LIABILITY_CLAIM_WORKFLOW_REPORT_SCHEMA.to_string(),
            generated_at: unix_now(),
            query: normalized,
            summary: LiabilityClaimWorkflowSummary {
                matching_claims,
                returned_claims: claims.len() as u64,
                provider_responses,
                accepted_responses,
                denied_responses,
                disputes,
                adjudications,
            },
            claims,
        })
    }

    pub fn record_credit_loss_lifecycle(
        &mut self,
        event: &SignedCreditLossLifecycle,
    ) -> Result<(), ReceiptStoreError> {
        if !event
            .verify_signature()
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        {
            return Err(ReceiptStoreError::Conflict(
                "credit loss lifecycle signature verification failed".to_string(),
            ));
        }

        let artifact = &event.body;
        let tx = self.connection.transaction()?;
        let existing = tx
            .query_row(
                "SELECT event_id FROM credit_loss_lifecycle WHERE event_id = ?1",
                params![artifact.event_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "credit loss lifecycle `{}` already exists",
                artifact.event_id
            )));
        }

        let bond_exists = tx
            .query_row(
                "SELECT bond_id FROM credit_bonds WHERE bond_id = ?1",
                params![artifact.bond_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if bond_exists.is_none() {
            return Err(ReceiptStoreError::NotFound(format!(
                "credit bond `{}` not found",
                artifact.bond_id
            )));
        }

        tx.execute(
            "INSERT INTO credit_loss_lifecycle (
                event_id, issued_at, bond_id, facility_id, capability_id, subject_key,
                tool_server, tool_name, event_kind, projected_bond_lifecycle_state,
                raw_json, signer_key, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                artifact.event_id,
                artifact.issued_at as i64,
                artifact.bond_id,
                artifact.report.summary.facility_id.as_deref(),
                artifact.report.summary.capability_id.as_deref(),
                artifact.report.summary.agent_subject.as_deref(),
                artifact.report.summary.tool_server.as_deref(),
                artifact.report.summary.tool_name.as_deref(),
                credit_loss_lifecycle_event_kind_label(artifact.event_kind),
                credit_bond_lifecycle_state_label(artifact.projected_bond_lifecycle_state),
                serde_json::to_string(event)?,
                event.signer_key.to_hex(),
                event.signature.to_hex(),
            ],
        )?;

        tx.execute(
            "UPDATE credit_bonds
             SET lifecycle_state = ?1
             WHERE bond_id = ?2",
            params![
                credit_bond_lifecycle_state_label(artifact.projected_bond_lifecycle_state),
                artifact.bond_id,
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn query_credit_loss_lifecycle(
        &self,
        query: &CreditLossLifecycleListQuery,
    ) -> Result<CreditLossLifecycleListReport, ReceiptStoreError> {
        let normalized = query.normalized();
        let mut statement = self.connection.prepare(
            "SELECT raw_json
             FROM credit_loss_lifecycle
             ORDER BY issued_at DESC, event_id DESC",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;

        let mut matching_events = 0_u64;
        let mut delinquency_events = 0_u64;
        let mut recovery_events = 0_u64;
        let mut reserve_release_events = 0_u64;
        let mut write_off_events = 0_u64;
        let mut events = Vec::new();

        for row in rows {
            let raw_json = row?;
            let event: SignedCreditLossLifecycle = serde_json::from_str(&raw_json)?;
            let body = &event.body;
            let summary = &body.report.summary;
            if normalized
                .event_id
                .as_deref()
                .is_some_and(|value| value != body.event_id)
            {
                continue;
            }
            if normalized
                .bond_id
                .as_deref()
                .is_some_and(|value| value != body.bond_id)
            {
                continue;
            }
            if normalized
                .facility_id
                .as_deref()
                .is_some_and(|value| summary.facility_id.as_deref() != Some(value))
            {
                continue;
            }
            if normalized
                .capability_id
                .as_deref()
                .is_some_and(|value| summary.capability_id.as_deref() != Some(value))
            {
                continue;
            }
            if normalized
                .agent_subject
                .as_deref()
                .is_some_and(|value| summary.agent_subject.as_deref() != Some(value))
            {
                continue;
            }
            if normalized
                .tool_server
                .as_deref()
                .is_some_and(|value| summary.tool_server.as_deref() != Some(value))
            {
                continue;
            }
            if normalized
                .tool_name
                .as_deref()
                .is_some_and(|value| summary.tool_name.as_deref() != Some(value))
            {
                continue;
            }
            if normalized
                .event_kind
                .is_some_and(|value| value != body.event_kind)
            {
                continue;
            }

            matching_events = matching_events.saturating_add(1);
            match body.event_kind {
                CreditLossLifecycleEventKind::Delinquency => {
                    delinquency_events = delinquency_events.saturating_add(1);
                }
                CreditLossLifecycleEventKind::Recovery => {
                    recovery_events = recovery_events.saturating_add(1);
                }
                CreditLossLifecycleEventKind::ReserveRelease => {
                    reserve_release_events = reserve_release_events.saturating_add(1);
                }
                CreditLossLifecycleEventKind::WriteOff => {
                    write_off_events = write_off_events.saturating_add(1);
                }
            }

            if events.len() < normalized.limit_or_default() {
                events.push(CreditLossLifecycleRow { event });
            }
        }

        Ok(CreditLossLifecycleListReport {
            schema: CREDIT_LOSS_LIFECYCLE_LIST_REPORT_SCHEMA.to_string(),
            generated_at: unix_now(),
            query: normalized,
            summary: CreditLossLifecycleListSummary {
                matching_events,
                returned_events: events.len() as u64,
                delinquency_events,
                recovery_events,
                reserve_release_events,
                write_off_events,
            },
            events,
        })
    }

    fn load_underwriting_appeals_by_decision(
        &self,
    ) -> Result<BTreeMap<String, Vec<UnderwritingAppealRecord>>, ReceiptStoreError> {
        let mut appeals_by_decision = BTreeMap::new();
        for appeal in load_underwriting_appeal_rows(&self.connection)? {
            appeals_by_decision
                .entry(appeal.decision_id.clone())
                .or_insert_with(Vec::new)
                .push(appeal);
        }
        Ok(appeals_by_decision)
    }

    pub fn list_tool_receipts(
        &self,
        limit: usize,
        capability_id: Option<&str>,
        tool_server: Option<&str>,
        tool_name: Option<&str>,
        decision_kind: Option<&str>,
    ) -> Result<Vec<ArcReceipt>, ReceiptStoreError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT raw_json
            FROM arc_tool_receipts
            WHERE (?1 IS NULL OR capability_id = ?1)
              AND (?2 IS NULL OR tool_server = ?2)
              AND (?3 IS NULL OR tool_name = ?3)
              AND (?4 IS NULL OR decision_kind = ?4)
            ORDER BY seq DESC
            LIMIT ?5
            "#,
        )?;
        let rows = statement.query_map(
            params![
                capability_id,
                tool_server,
                tool_name,
                decision_kind,
                limit as i64,
            ],
            |row| row.get::<_, String>(0),
        )?;

        rows.map(|row| {
            let raw_json = row?;
            Ok(serde_json::from_str(&raw_json)?)
        })
        .collect()
    }

    /// List all tool receipts attributed to a given subject public key.
    ///
    /// Uses the persisted `subject_key` column when present and falls back to
    /// the capability lineage join for older rows.
    pub fn list_tool_receipts_for_subject(
        &self,
        subject_key: &str,
    ) -> Result<Vec<ArcReceipt>, ReceiptStoreError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT r.raw_json
            FROM arc_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE COALESCE(r.subject_key, cl.subject_key) = ?1
            ORDER BY r.timestamp ASC, r.seq ASC
            "#,
        )?;
        let rows = statement.query_map(params![subject_key], |row| row.get::<_, String>(0))?;

        rows.map(|row| {
            let raw_json = row?;
            Ok(serde_json::from_str(&raw_json)?)
        })
        .collect()
    }

    pub fn list_tool_receipts_after_seq(
        &self,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<StoredToolReceipt>, ReceiptStoreError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT seq, raw_json
            FROM arc_tool_receipts
            WHERE seq > ?1
            ORDER BY seq ASC
            LIMIT ?2
            "#,
        )?;
        let rows = statement.query_map(params![after_seq as i64, limit as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (seq, raw_json) = row?;
            Ok(StoredToolReceipt {
                seq: seq.max(0) as u64,
                receipt: serde_json::from_str(&raw_json)?,
            })
        })
        .collect()
    }

    pub fn list_child_receipts(
        &self,
        limit: usize,
        session_id: Option<&str>,
        parent_request_id: Option<&str>,
        request_id: Option<&str>,
        operation_kind: Option<&str>,
        terminal_state: Option<&str>,
    ) -> Result<Vec<ChildRequestReceipt>, ReceiptStoreError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT raw_json
            FROM arc_child_receipts
            WHERE (?1 IS NULL OR session_id = ?1)
              AND (?2 IS NULL OR parent_request_id = ?2)
              AND (?3 IS NULL OR request_id = ?3)
              AND (?4 IS NULL OR operation_kind = ?4)
              AND (?5 IS NULL OR terminal_state = ?5)
            ORDER BY seq DESC
            LIMIT ?6
            "#,
        )?;
        let rows = statement.query_map(
            params![
                session_id,
                parent_request_id,
                request_id,
                operation_kind,
                terminal_state,
                limit as i64,
            ],
            |row| row.get::<_, String>(0),
        )?;

        rows.map(|row| {
            let raw_json = row?;
            Ok(serde_json::from_str(&raw_json)?)
        })
        .collect()
    }

    pub fn list_child_receipts_after_seq(
        &self,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<StoredChildReceipt>, ReceiptStoreError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT seq, raw_json
            FROM arc_child_receipts
            WHERE seq > ?1
            ORDER BY seq ASC
            LIMIT ?2
            "#,
        )?;
        let rows = statement.query_map(params![after_seq as i64, limit as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (seq, raw_json) = row?;
            Ok(StoredChildReceipt {
                seq: seq.max(0) as u64,
                receipt: serde_json::from_str(&raw_json)?,
            })
        })
        .collect()
    }

    pub fn import_federated_evidence_share(
        &mut self,
        import: &FederatedEvidenceShareImport,
    ) -> Result<FederatedEvidenceShareSummary, ReceiptStoreError> {
        let imported_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let tx = self.connection.transaction()?;
        tx.execute(
            r#"
            INSERT INTO federated_evidence_shares (
                share_id,
                manifest_hash,
                imported_at,
                exported_at,
                issuer,
                partner,
                signer_public_key,
                require_proofs,
                query_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(share_id) DO UPDATE SET
                manifest_hash = excluded.manifest_hash,
                imported_at = excluded.imported_at,
                exported_at = excluded.exported_at,
                issuer = excluded.issuer,
                partner = excluded.partner,
                signer_public_key = excluded.signer_public_key,
                require_proofs = excluded.require_proofs,
                query_json = excluded.query_json
            "#,
            params![
                import.share_id,
                import.manifest_hash,
                imported_at as i64,
                import.exported_at as i64,
                import.issuer,
                import.partner,
                import.signer_public_key,
                if import.require_proofs { 1_i64 } else { 0_i64 },
                import.query_json,
            ],
        )?;

        let lineage_by_capability = import
            .capability_lineage
            .iter()
            .map(|snapshot| (snapshot.capability_id.as_str(), snapshot))
            .collect::<BTreeMap<_, _>>();

        for snapshot in &import.capability_lineage {
            tx.execute(
                r#"
                INSERT INTO federated_share_capability_lineage (
                    share_id,
                    capability_id,
                    subject_key,
                    issuer_key,
                    issued_at,
                    expires_at,
                    grants_json,
                    delegation_depth,
                    parent_capability_id
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                ON CONFLICT(share_id, capability_id) DO UPDATE SET
                    subject_key = excluded.subject_key,
                    issuer_key = excluded.issuer_key,
                    issued_at = excluded.issued_at,
                    expires_at = excluded.expires_at,
                    grants_json = excluded.grants_json,
                    delegation_depth = excluded.delegation_depth,
                    parent_capability_id = excluded.parent_capability_id
                "#,
                params![
                    import.share_id,
                    snapshot.capability_id,
                    snapshot.subject_key,
                    snapshot.issuer_key,
                    snapshot.issued_at as i64,
                    snapshot.expires_at as i64,
                    snapshot.grants_json,
                    snapshot.delegation_depth as i64,
                    snapshot.parent_capability_id,
                ],
            )?;
        }

        for record in &import.tool_receipts {
            let attribution = extract_receipt_attribution(&record.receipt);
            let lineage_subject = lineage_by_capability
                .get(record.receipt.capability_id.as_str())
                .map(|snapshot| snapshot.subject_key.as_str());
            let lineage_issuer = lineage_by_capability
                .get(record.receipt.capability_id.as_str())
                .map(|snapshot| snapshot.issuer_key.as_str());
            tx.execute(
                r#"
                INSERT INTO federated_share_tool_receipts (
                    share_id,
                    seq,
                    receipt_id,
                    timestamp,
                    capability_id,
                    subject_key,
                    issuer_key,
                    raw_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                ON CONFLICT(share_id, seq) DO UPDATE SET
                    receipt_id = excluded.receipt_id,
                    timestamp = excluded.timestamp,
                    capability_id = excluded.capability_id,
                    subject_key = excluded.subject_key,
                    issuer_key = excluded.issuer_key,
                    raw_json = excluded.raw_json
                "#,
                params![
                    import.share_id,
                    record.seq as i64,
                    record.receipt.id,
                    record.receipt.timestamp as i64,
                    record.receipt.capability_id,
                    attribution
                        .subject_key
                        .or_else(|| lineage_subject.map(ToOwned::to_owned)),
                    attribution
                        .issuer_key
                        .or_else(|| lineage_issuer.map(ToOwned::to_owned)),
                    serde_json::to_string(&record.receipt)?,
                ],
            )?;
        }

        tx.commit()?;

        Ok(FederatedEvidenceShareSummary {
            share_id: import.share_id.clone(),
            manifest_hash: import.manifest_hash.clone(),
            imported_at,
            exported_at: import.exported_at,
            issuer: import.issuer.clone(),
            partner: import.partner.clone(),
            signer_public_key: import.signer_public_key.clone(),
            require_proofs: import.require_proofs,
            tool_receipts: import.tool_receipts.len() as u64,
            capability_lineage: import.capability_lineage.len() as u64,
        })
    }

    pub fn get_federated_share_for_capability(
        &self,
        capability_id: &str,
    ) -> Result<Option<(FederatedEvidenceShareSummary, CapabilitySnapshot)>, ReceiptStoreError>
    {
        let row = self
            .connection
            .query_row(
                r#"
                SELECT
                    s.share_id,
                    s.manifest_hash,
                    s.imported_at,
                    s.exported_at,
                    s.issuer,
                    s.partner,
                    s.signer_public_key,
                    s.require_proofs,
                    (SELECT COUNT(*) FROM federated_share_tool_receipts r WHERE r.share_id = s.share_id),
                    (SELECT COUNT(*) FROM federated_share_capability_lineage c WHERE c.share_id = s.share_id),
                    l.capability_id,
                    l.subject_key,
                    l.issuer_key,
                    l.issued_at,
                    l.expires_at,
                    l.grants_json,
                    l.delegation_depth,
                    l.parent_capability_id
                FROM federated_share_capability_lineage l
                INNER JOIN federated_evidence_shares s ON s.share_id = l.share_id
                WHERE l.capability_id = ?1
                ORDER BY s.imported_at DESC, s.share_id DESC
                LIMIT 1
                "#,
                params![capability_id],
                |row| {
                    Ok((
                        FederatedEvidenceShareSummary {
                            share_id: row.get::<_, String>(0)?,
                            manifest_hash: row.get::<_, String>(1)?,
                            imported_at: row.get::<_, i64>(2)?.max(0) as u64,
                            exported_at: row.get::<_, i64>(3)?.max(0) as u64,
                            issuer: row.get::<_, String>(4)?,
                            partner: row.get::<_, String>(5)?,
                            signer_public_key: row.get::<_, String>(6)?,
                            require_proofs: row.get::<_, i64>(7)? != 0,
                            tool_receipts: row.get::<_, i64>(8)?.max(0) as u64,
                            capability_lineage: row.get::<_, i64>(9)?.max(0) as u64,
                        },
                        CapabilitySnapshot {
                            capability_id: row.get::<_, String>(10)?,
                            subject_key: row.get::<_, String>(11)?,
                            issuer_key: row.get::<_, String>(12)?,
                            issued_at: row.get::<_, i64>(13)?.max(0) as u64,
                            expires_at: row.get::<_, i64>(14)?.max(0) as u64,
                            grants_json: row.get::<_, String>(15)?,
                            delegation_depth: row.get::<_, i64>(16)?.max(0) as u64,
                            parent_capability_id: row.get::<_, Option<String>>(17)?,
                        },
                    ))
                },
            )
            .optional()?;
        Ok(row)
    }

    pub fn list_federated_share_subject_corpora(
        &self,
        subject_key: &str,
        since: Option<u64>,
        until: Option<u64>,
    ) -> Result<Vec<FederatedShareSubjectCorpus>, ReceiptStoreError> {
        let mut share_ids = self
            .connection
            .prepare(
                r#"
                SELECT DISTINCT share_id
                FROM federated_share_tool_receipts
                WHERE subject_key = ?1
                  AND (?2 IS NULL OR timestamp >= ?2)
                  AND (?3 IS NULL OR timestamp <= ?3)
                ORDER BY share_id
                "#,
            )?
            .query_map(
                params![
                    subject_key,
                    since.map(|value| value as i64),
                    until.map(|value| value as i64)
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?;

        share_ids.sort();
        let mut results = Vec::new();
        for share_id in share_ids {
            let summary = self
                .connection
                .query_row(
                    r#"
                    SELECT
                        share_id,
                        manifest_hash,
                        imported_at,
                        exported_at,
                        issuer,
                        partner,
                        signer_public_key,
                        require_proofs,
                        (SELECT COUNT(*) FROM federated_share_tool_receipts r WHERE r.share_id = s.share_id),
                        (SELECT COUNT(*) FROM federated_share_capability_lineage c WHERE c.share_id = s.share_id)
                    FROM federated_evidence_shares s
                    WHERE share_id = ?1
                    "#,
                    params![share_id],
                    |row| {
                        Ok(FederatedEvidenceShareSummary {
                            share_id: row.get::<_, String>(0)?,
                            manifest_hash: row.get::<_, String>(1)?,
                            imported_at: row.get::<_, i64>(2)?.max(0) as u64,
                            exported_at: row.get::<_, i64>(3)?.max(0) as u64,
                            issuer: row.get::<_, String>(4)?,
                            partner: row.get::<_, String>(5)?,
                            signer_public_key: row.get::<_, String>(6)?,
                            require_proofs: row.get::<_, i64>(7)? != 0,
                            tool_receipts: row.get::<_, i64>(8)?.max(0) as u64,
                            capability_lineage: row.get::<_, i64>(9)?.max(0) as u64,
                        })
                    },
                )?;

            let receipts = self
                .connection
                .prepare(
                    r#"
                    SELECT seq, raw_json
                    FROM federated_share_tool_receipts
                    WHERE share_id = ?1
                      AND subject_key = ?2
                      AND (?3 IS NULL OR timestamp >= ?3)
                      AND (?4 IS NULL OR timestamp <= ?4)
                    ORDER BY seq ASC
                    "#,
                )?
                .query_map(
                    params![
                        summary.share_id,
                        subject_key,
                        since.map(|value| value as i64),
                        until.map(|value| value as i64)
                    ],
                    |row| {
                        let raw_json = row.get::<_, String>(1)?;
                        Ok(StoredToolReceipt {
                            seq: row.get::<_, i64>(0)?.max(0) as u64,
                            receipt: serde_json::from_str(&raw_json).map_err(|error| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    raw_json.len(),
                                    rusqlite::types::Type::Text,
                                    Box::new(error),
                                )
                            })?,
                        })
                    },
                )?
                .collect::<Result<Vec<_>, _>>()?;

            let capabilities = self
                .connection
                .prepare(
                    r#"
                    SELECT
                        capability_id,
                        subject_key,
                        issuer_key,
                        issued_at,
                        expires_at,
                        grants_json,
                        delegation_depth,
                        parent_capability_id
                    FROM federated_share_capability_lineage
                    WHERE share_id = ?1
                      AND (subject_key = ?2 OR issuer_key = ?2)
                    ORDER BY issued_at ASC, capability_id ASC
                    "#,
                )?
                .query_map(params![summary.share_id, subject_key], |row| {
                    Ok(CapabilitySnapshot {
                        capability_id: row.get::<_, String>(0)?,
                        subject_key: row.get::<_, String>(1)?,
                        issuer_key: row.get::<_, String>(2)?,
                        issued_at: row.get::<_, i64>(3)?.max(0) as u64,
                        expires_at: row.get::<_, i64>(4)?.max(0) as u64,
                        grants_json: row.get::<_, String>(5)?,
                        delegation_depth: row.get::<_, i64>(6)?.max(0) as u64,
                        parent_capability_id: row.get::<_, Option<String>>(7)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;

            results.push((summary, receipts, capabilities));
        }

        Ok(results)
    }

    pub fn record_federated_lineage_bridge(
        &mut self,
        local_capability_id: &str,
        parent_capability_id: &str,
        share_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        self.connection.execute(
            r#"
            INSERT INTO federated_lineage_bridges (
                local_capability_id,
                parent_capability_id,
                share_id
            ) VALUES (?1, ?2, ?3)
            ON CONFLICT(local_capability_id) DO UPDATE SET
                parent_capability_id = excluded.parent_capability_id,
                share_id = excluded.share_id
            "#,
            params![local_capability_id, parent_capability_id, share_id],
        )?;
        Ok(())
    }

    fn federated_lineage_bridge_parent(
        &self,
        local_capability_id: &str,
    ) -> Result<Option<String>, ReceiptStoreError> {
        self.connection
            .query_row(
                r#"
                SELECT parent_capability_id
                FROM federated_lineage_bridges
                WHERE local_capability_id = ?1
                "#,
                params![local_capability_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn get_combined_lineage(
        &self,
        capability_id: &str,
    ) -> Result<Option<arc_kernel::CapabilitySnapshot>, ReceiptStoreError> {
        if let Some(mut snapshot) =
            self.get_lineage(capability_id)
                .map_err(|error| match error {
                    arc_kernel::CapabilityLineageError::Sqlite(error) => {
                        ReceiptStoreError::Sqlite(error)
                    }
                    arc_kernel::CapabilityLineageError::Json(error) => {
                        ReceiptStoreError::Json(error)
                    }
                })?
        {
            if snapshot.parent_capability_id.is_none() {
                snapshot.parent_capability_id =
                    self.federated_lineage_bridge_parent(&snapshot.capability_id)?;
            }
            return Ok(Some(snapshot));
        }
        Ok(self
            .get_federated_share_for_capability(capability_id)?
            .map(|(_, snapshot)| snapshot))
    }

    pub fn get_combined_delegation_chain(
        &self,
        capability_id: &str,
    ) -> Result<Vec<arc_kernel::CapabilitySnapshot>, ReceiptStoreError> {
        let mut chain = Vec::new();
        let mut current = Some(capability_id.to_string());
        let mut seen = BTreeSet::new();

        while let Some(current_capability_id) = current.take() {
            if !seen.insert(current_capability_id.clone()) || chain.len() >= 32 {
                break;
            }
            let Some(snapshot) = self.get_combined_lineage(&current_capability_id)? else {
                break;
            };
            current = snapshot.parent_capability_id.clone();
            chain.push(snapshot);
        }

        chain.reverse();
        Ok(chain)
    }

    /// Append a ArcReceipt and return the AUTOINCREMENT seq assigned.
    ///
    /// Returns 0 if the receipt was a duplicate (ON CONFLICT DO NOTHING).
    pub fn append_arc_receipt_returning_seq(
        &mut self,
        receipt: &ArcReceipt,
    ) -> Result<u64, ReceiptStoreError> {
        let raw_json = serde_json::to_string(receipt)?;
        let attribution = extract_receipt_attribution(receipt);
        self.connection.execute(
            r#"
            INSERT INTO arc_tool_receipts (
                receipt_id,
                timestamp,
                capability_id,
                subject_key,
                issuer_key,
                grant_index,
                tool_server,
                tool_name,
                decision_kind,
                policy_hash,
                content_hash,
                raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(receipt_id) DO NOTHING
            "#,
            params![
                receipt.id,
                receipt.timestamp,
                receipt.capability_id,
                attribution.subject_key,
                attribution.issuer_key,
                attribution.grant_index.map(i64::from),
                receipt.tool_server,
                receipt.tool_name,
                decision_kind(&receipt.decision),
                receipt.policy_hash,
                receipt.content_hash,
                raw_json,
            ],
        )?;
        let seq = self.connection.last_insert_rowid().max(0) as u64;
        Ok(seq)
    }

    /// Store a signed KernelCheckpoint in the kernel_checkpoints table.
    pub fn store_checkpoint(
        &mut self,
        checkpoint: &KernelCheckpoint,
    ) -> Result<(), ReceiptStoreError> {
        let statement_json = serde_json::to_string(&checkpoint.body)?;
        self.connection.execute(
            r#"
            INSERT INTO kernel_checkpoints (
                checkpoint_seq, batch_start_seq, batch_end_seq, tree_size,
                merkle_root, issued_at, statement_json, signature, kernel_key
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            params![
                checkpoint.body.checkpoint_seq as i64,
                checkpoint.body.batch_start_seq as i64,
                checkpoint.body.batch_end_seq as i64,
                checkpoint.body.tree_size as i64,
                checkpoint.body.merkle_root.to_hex(),
                checkpoint.body.issued_at as i64,
                statement_json,
                checkpoint.signature.to_hex(),
                checkpoint.body.kernel_key.to_hex(),
            ],
        )?;
        Ok(())
    }

    /// Load a KernelCheckpoint by its checkpoint_seq.
    pub fn load_checkpoint_by_seq(
        &self,
        checkpoint_seq: u64,
    ) -> Result<Option<KernelCheckpoint>, ReceiptStoreError> {
        let row = self
            .connection
            .query_row(
                r#"
                SELECT statement_json, signature
                FROM kernel_checkpoints
                WHERE checkpoint_seq = ?1
                "#,
                params![checkpoint_seq as i64],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;

        match row {
            None => Ok(None),
            Some((statement_json, signature_hex)) => {
                let body: KernelCheckpointBody = serde_json::from_str(&statement_json)?;
                let signature = Signature::from_hex(&signature_hex)
                    .map_err(|e| ReceiptStoreError::CryptoDecode(e.to_string()))?;
                Ok(Some(KernelCheckpoint { body, signature }))
            }
        }
    }

    /// Return canonical JSON bytes for receipts with seq in [start_seq, end_seq], ordered by seq.
    ///
    /// Uses RFC 8785 canonical JSON for deterministic Merkle leaf hashing.
    pub fn receipts_canonical_bytes_range(
        &self,
        start_seq: u64,
        end_seq: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>, ReceiptStoreError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT seq, raw_json
            FROM arc_tool_receipts
            WHERE seq >= ?1 AND seq <= ?2
            ORDER BY seq ASC
            "#,
        )?;
        let rows = statement.query_map(params![start_seq as i64, end_seq as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut result = Vec::new();
        for row in rows {
            let (seq, raw_json) = row?;
            let receipt: ArcReceipt = serde_json::from_str(&raw_json)?;
            let canonical = canonical_json_bytes(&receipt)
                .map_err(|e| ReceiptStoreError::Canonical(e.to_string()))?;
            result.push((seq.max(0) as u64, canonical));
        }
        Ok(result)
    }

    /// Return the current on-disk size of the database in bytes.
    ///
    /// Uses `PRAGMA page_count` and `PRAGMA page_size` to compute the size
    /// without requiring a filesystem stat, which is consistent in WAL mode.
    pub fn db_size_bytes(&self) -> Result<u64, ReceiptStoreError> {
        let page_count: i64 = self
            .connection
            .query_row("PRAGMA page_count", [], |row| row.get(0))?;
        let page_size: i64 = self
            .connection
            .query_row("PRAGMA page_size", [], |row| row.get(0))?;
        Ok((page_count.max(0) as u64) * (page_size.max(0) as u64))
    }

    /// Return the Unix timestamp (seconds) of the oldest receipt in the live
    /// database, or `None` if there are no receipts.
    pub fn oldest_receipt_timestamp(&self) -> Result<Option<u64>, ReceiptStoreError> {
        let ts = self.connection.query_row(
            "SELECT MIN(timestamp) FROM arc_tool_receipts",
            [],
            |row| row.get::<_, Option<i64>>(0),
        )?;
        Ok(ts.map(|t| t.max(0) as u64))
    }

    /// Archive all receipts with `timestamp < cutoff_unix_secs` to an external
    /// SQLite file, then delete them from the live database.
    ///
    /// Checkpoint rows whose entire batch (`batch_end_seq`) falls within the
    /// archived receipt range are also copied to the archive. Partial batches
    /// are never archived to avoid breaking inclusion proofs.
    ///
    /// Returns the number of receipt rows deleted from the live database.
    pub fn archive_receipts_before(
        &mut self,
        cutoff_unix_secs: u64,
        archive_path: &str,
    ) -> Result<u64, ReceiptStoreError> {
        // Escape single quotes in the path to safely embed it in an ATTACH statement.
        let escaped_path = archive_path.replace('\'', "''");

        // Attach the archive database.
        self.connection
            .execute_batch(&format!("ATTACH DATABASE '{escaped_path}' AS archive"))?;

        // Create archive tables with the same schema as the main database.
        self.connection.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS archive.arc_tool_receipts (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                timestamp INTEGER NOT NULL,
                capability_id TEXT NOT NULL,
                subject_key TEXT,
                issuer_key TEXT,
                grant_index INTEGER,
                tool_server TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                decision_kind TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS archive.arc_child_receipts (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                timestamp INTEGER NOT NULL,
                session_id TEXT NOT NULL,
                parent_request_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                operation_kind TEXT NOT NULL,
                terminal_state TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                outcome_hash TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS archive.kernel_checkpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                checkpoint_seq INTEGER NOT NULL UNIQUE,
                batch_start_seq INTEGER NOT NULL,
                batch_end_seq INTEGER NOT NULL,
                tree_size INTEGER NOT NULL,
                merkle_root TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                statement_json TEXT NOT NULL,
                signature TEXT NOT NULL,
                kernel_key TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS archive.capability_lineage (
                capability_id        TEXT PRIMARY KEY,
                subject_key          TEXT NOT NULL,
                issuer_key           TEXT NOT NULL,
                issued_at            INTEGER NOT NULL,
                expires_at           INTEGER NOT NULL,
                grants_json          TEXT NOT NULL,
                delegation_depth     INTEGER NOT NULL DEFAULT 0,
                parent_capability_id TEXT
            );
            "#,
        )?;

        let cutoff = cutoff_unix_secs as i64;

        // Copy qualifying receipts to the archive (ignore duplicates from prior runs).
        self.connection.execute(
            "INSERT OR IGNORE INTO archive.arc_tool_receipts \
             SELECT * FROM main.arc_tool_receipts WHERE timestamp < ?1",
            params![cutoff],
        )?;
        self.connection.execute(
            "INSERT OR IGNORE INTO archive.arc_child_receipts \
             SELECT * FROM main.arc_child_receipts WHERE timestamp < ?1",
            params![cutoff],
        )?;
        self.connection.execute(
            "INSERT OR IGNORE INTO archive.capability_lineage
             SELECT DISTINCT cl.*
             FROM main.capability_lineage cl
             INNER JOIN main.arc_tool_receipts r ON r.capability_id = cl.capability_id
             WHERE r.timestamp < ?1",
            params![cutoff],
        )?;

        // Find the maximum seq among archived receipts (for checkpoint filtering).
        let max_archived_seq: Option<i64> = self.connection.query_row(
            "SELECT MAX(seq) FROM main.arc_tool_receipts WHERE timestamp < ?1",
            params![cutoff],
            |row| row.get(0),
        )?;

        if let Some(max_seq) = max_archived_seq {
            // Copy checkpoint rows whose full batch is covered by the archived receipts.
            // Never archive a checkpoint whose batch_end_seq exceeds the max archived seq
            // because that would leave a partial batch in the archive.
            self.connection.execute(
                "INSERT OR IGNORE INTO archive.kernel_checkpoints \
                 SELECT * FROM main.kernel_checkpoints WHERE batch_end_seq <= ?1",
                params![max_seq],
            )?;

            // Verify that every checkpoint covering the archived range is now present
            // in the archive. If any checkpoint failed to transfer, refuse to delete the
            // receipts from the live database to preserve inclusion-proof integrity.
            let live_count: i64 = self.connection.query_row(
                "SELECT COUNT(*) FROM main.kernel_checkpoints WHERE batch_end_seq <= ?1",
                params![max_seq],
                |row| row.get(0),
            )?;
            let archive_count: i64 = self.connection.query_row(
                "SELECT COUNT(*) FROM archive.kernel_checkpoints WHERE batch_end_seq <= ?1",
                params![max_seq],
                |row| row.get(0),
            )?;
            if archive_count < live_count {
                // Detach the archive before returning the error to avoid leaving
                // the database in an attached state.
                let _ = self.connection.execute_batch("DETACH DATABASE archive");
                return Err(ReceiptStoreError::Canonical(format!(
                    "checkpoint co-archival incomplete: {live_count} checkpoints in live, \
                     only {archive_count} transferred to archive; aborting receipt deletion \
                     to preserve inclusion-proof integrity"
                )));
            }
        }

        // Delete archived receipts from the live database.
        let deleted = self.connection.execute(
            "DELETE FROM main.arc_tool_receipts WHERE timestamp < ?1",
            params![cutoff],
        )? as u64;
        self.connection.execute(
            "DELETE FROM main.arc_child_receipts WHERE timestamp < ?1",
            params![cutoff],
        )?;

        // Detach the archive and checkpoint WAL.
        self.connection.execute_batch("DETACH DATABASE archive")?;
        self.connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;

        Ok(deleted)
    }

    /// Check time and size thresholds and archive receipts if either is exceeded.
    ///
    /// - Time threshold: receipts older than `config.retention_days` days are archived.
    /// - Size threshold: if `db_size_bytes()` exceeds `config.max_size_bytes`, receipts
    ///   older than the median timestamp are archived (removes roughly half the receipts).
    ///
    /// Returns the number of receipt rows archived (0 if no threshold was exceeded).
    pub fn rotate_if_needed(&mut self, config: &RetentionConfig) -> Result<u64, ReceiptStoreError> {
        // Check time threshold.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let time_cutoff = now.saturating_sub(config.retention_days.saturating_mul(86_400));
        let oldest = self.oldest_receipt_timestamp()?;

        if let Some(oldest_ts) = oldest {
            if oldest_ts < time_cutoff {
                return self.archive_receipts_before(time_cutoff, &config.archive_path);
            }
        }

        // Check size threshold.
        let size = self.db_size_bytes()?;
        if size > config.max_size_bytes {
            // Use the median timestamp as the cutoff to archive roughly half the receipts.
            let median_cutoff: Option<i64> = self
                .connection
                .query_row(
                    r#"
                    SELECT timestamp FROM arc_tool_receipts
                    ORDER BY timestamp
                    LIMIT 1
                    OFFSET (SELECT COUNT(*) FROM arc_tool_receipts) / 2
                    "#,
                    [],
                    |row| row.get(0),
                )
                .optional()?;

            if let Some(cutoff) = median_cutoff {
                return self.archive_receipts_before(cutoff.max(0) as u64, &config.archive_path);
            }
        }

        Ok(0)
    }

    /// Internal implementation for `query_receipts` (called from `receipt_query` module).
    ///
    /// Requires access to the private `connection` field, so it lives here in `receipt_store`.
    pub(crate) fn query_receipts_impl(
        &self,
        query: &ReceiptQuery,
    ) -> Result<ReceiptQueryResult, ReceiptStoreError> {
        // Validate the `outcome` filter against the known decision_kind values.
        // Silently accepting unknown values would return zero results and could
        // mask caller bugs; fail explicitly instead.
        const VALID_OUTCOMES: &[&str] = &["allow", "deny", "cancelled", "incomplete"];
        if let Some(outcome) = query.outcome.as_deref() {
            if !VALID_OUTCOMES.contains(&outcome) {
                return Err(ReceiptStoreError::InvalidOutcome(format!(
                    "unknown outcome filter {:?}; valid values are: allow, deny, cancelled, incomplete",
                    outcome
                )));
            }
        }

        let limit = query.limit.clamp(1, MAX_QUERY_LIMIT);

        // Both queries share the same 9 filter parameters.
        // Parameters:
        //   ?1  capability_id
        //   ?2  tool_server
        //   ?3  tool_name
        //   ?4  outcome (decision_kind)
        //   ?5  since (timestamp >=, inclusive)
        //   ?6  until (timestamp <=, inclusive)
        //   ?7  min_cost (json_extract cost_charged >=)
        //   ?8  max_cost (json_extract cost_charged <=)
        //   ?9  agent_subject (receipt subject_key, falling back to capability_lineage)
        //
        // Data query also uses:
        //   ?10 cursor (seq >, exclusive)
        //   ?11 limit
        //
        // When agent_subject is None, the LEFT JOIN produces NULL for cl.subject_key,
        // and the (?9 IS NULL OR ...) guard passes -- no rows are filtered out.
        let data_sql = r#"
            SELECT r.seq, r.raw_json
            FROM arc_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.decision_kind = ?4)
              AND (?5 IS NULL OR r.timestamp >= ?5)
              AND (?6 IS NULL OR r.timestamp <= ?6)
              AND (?7 IS NULL OR CAST(json_extract(r.raw_json, '$.metadata.financial.cost_charged') AS INTEGER) >= ?7)
              AND (?8 IS NULL OR CAST(json_extract(r.raw_json, '$.metadata.financial.cost_charged') AS INTEGER) <= ?8)
              AND (?9 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?9)
              AND (?10 IS NULL OR r.seq > ?10)
            ORDER BY r.seq ASC
            LIMIT ?11
        "#;

        // Count query uses identical WHERE clause but no cursor and no LIMIT.
        // total_count reflects the full filtered set regardless of pagination.
        let count_sql = r#"
            SELECT COUNT(*)
            FROM arc_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.decision_kind = ?4)
              AND (?5 IS NULL OR r.timestamp >= ?5)
              AND (?6 IS NULL OR r.timestamp <= ?6)
              AND (?7 IS NULL OR CAST(json_extract(r.raw_json, '$.metadata.financial.cost_charged') AS INTEGER) >= ?7)
              AND (?8 IS NULL OR CAST(json_extract(r.raw_json, '$.metadata.financial.cost_charged') AS INTEGER) <= ?8)
              AND (?9 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?9)
        "#;

        let cap_id = query.capability_id.as_deref();
        let tool_srv = query.tool_server.as_deref();
        let tool_nm = query.tool_name.as_deref();
        let outcome = query.outcome.as_deref();
        let since = query.since.map(|v| v as i64);
        let until = query.until.map(|v| v as i64);
        let min_cost = query.min_cost.map(|v| v as i64);
        let max_cost = query.max_cost.map(|v| v as i64);
        let agent_sub = query.agent_subject.as_deref();
        // Convert cursor to signed i64 for SQLite. SQLite AUTOINCREMENT seq
        // values are bounded by i64::MAX; a cursor above that can never be
        // exceeded. Convert with a checked cast: on overflow return an empty
        // receipts page (the cursor excludes everything) while still reporting
        // the correct total_count for the uncursored filter set.
        let cursor_i64: Option<i64> = match query.cursor {
            None => None,
            Some(c) => match i64::try_from(c) {
                Ok(v) => Some(v),
                Err(_) => {
                    // cursor > i64::MAX: no AUTOINCREMENT seq can exceed it.
                    // Run only the count query (no cursor applied) and return empty.
                    let total_count: u64 = self
                        .connection
                        .query_row(
                            count_sql,
                            params![
                                cap_id, tool_srv, tool_nm, outcome, since, until, min_cost,
                                max_cost, agent_sub,
                            ],
                            |row| row.get::<_, i64>(0),
                        )
                        .map(|n| n.max(0) as u64)?;
                    return Ok(ReceiptQueryResult {
                        receipts: Vec::new(),
                        total_count,
                        next_cursor: None,
                    });
                }
            },
        };

        // Execute data query.
        let mut stmt = self.connection.prepare(data_sql)?;
        let rows = stmt.query_map(
            params![
                cap_id,
                tool_srv,
                tool_nm,
                outcome,
                since,
                until,
                min_cost,
                max_cost,
                agent_sub,
                cursor_i64,
                limit as i64,
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )?;

        let mut receipts = Vec::new();
        for row in rows {
            let (seq, raw_json) = row?;
            let receipt: ArcReceipt = serde_json::from_str(&raw_json)?;
            receipts.push(StoredToolReceipt {
                seq: seq.max(0) as u64,
                receipt,
            });
        }

        // Execute count query (same filters, no cursor, no limit).
        let total_count: u64 = self
            .connection
            .query_row(
                count_sql,
                params![
                    cap_id, tool_srv, tool_nm, outcome, since, until, min_cost, max_cost,
                    agent_sub,
                ],
                |row| row.get::<_, i64>(0),
            )
            .map(|n| n.max(0) as u64)?;

        // next_cursor is Some(last_seq) when the page is full (more results may exist).
        let next_cursor = if receipts.len() == limit {
            receipts.last().map(|r| r.seq)
        } else {
            None
        };

        Ok(ReceiptQueryResult {
            receipts,
            total_count,
            next_cursor,
        })
    }

    pub fn query_receipt_analytics(
        &self,
        query: &ReceiptAnalyticsQuery,
    ) -> Result<ReceiptAnalyticsResponse, ReceiptStoreError> {
        let group_limit = query
            .group_limit
            .unwrap_or(50)
            .clamp(1, MAX_ANALYTICS_GROUP_LIMIT);
        let time_bucket = query.time_bucket.unwrap_or(AnalyticsTimeBucket::Day);
        let bucket_width = time_bucket.width_secs() as i64;

        let capability_id = query.capability_id.as_deref();
        let tool_server = query.tool_server.as_deref();
        let tool_name = query.tool_name.as_deref();
        let since = query.since.map(|value| value as i64);
        let until = query.until.map(|value| value as i64);
        let agent_subject = query.agent_subject.as_deref();

        let summary_sql = r#"
            SELECT
                COUNT(*) AS total_receipts,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'allow' THEN 1 ELSE 0 END), 0) AS allow_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'deny' THEN 1 ELSE 0 END), 0) AS deny_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'cancelled' THEN 1 ELSE 0 END), 0) AS cancelled_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'incomplete' THEN 1 ELSE 0 END), 0) AS incomplete_count,
                COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, '$.metadata.financial.cost_charged'), 0) AS INTEGER)), 0) AS total_cost_charged,
                COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, '$.metadata.financial.attempted_cost'), 0) AS INTEGER)), 0) AS total_attempted_cost
            FROM arc_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
        "#;
        let summary = self.connection.query_row(
            summary_sql,
            params![
                capability_id,
                tool_server,
                tool_name,
                since,
                until,
                agent_subject
            ],
            |row| {
                Ok(ReceiptAnalyticsMetrics::from_raw(
                    row.get::<_, i64>(0)?.max(0) as u64,
                    row.get::<_, i64>(1)?.max(0) as u64,
                    row.get::<_, i64>(2)?.max(0) as u64,
                    row.get::<_, i64>(3)?.max(0) as u64,
                    row.get::<_, i64>(4)?.max(0) as u64,
                    row.get::<_, i64>(5)?.max(0) as u64,
                    row.get::<_, i64>(6)?.max(0) as u64,
                ))
            },
        )?;

        let by_agent_sql = r#"
            SELECT
                COALESCE(r.subject_key, cl.subject_key) AS subject_key,
                COUNT(*) AS total_receipts,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'allow' THEN 1 ELSE 0 END), 0) AS allow_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'deny' THEN 1 ELSE 0 END), 0) AS deny_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'cancelled' THEN 1 ELSE 0 END), 0) AS cancelled_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'incomplete' THEN 1 ELSE 0 END), 0) AS incomplete_count,
                COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, '$.metadata.financial.cost_charged'), 0) AS INTEGER)), 0) AS total_cost_charged,
                COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, '$.metadata.financial.attempted_cost'), 0) AS INTEGER)), 0) AS total_attempted_cost
            FROM arc_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
              AND COALESCE(r.subject_key, cl.subject_key) IS NOT NULL
            GROUP BY COALESCE(r.subject_key, cl.subject_key)
            ORDER BY total_receipts DESC, subject_key ASC
            LIMIT ?7
        "#;
        let by_agent = self
            .connection
            .prepare(by_agent_sql)?
            .query_map(
                params![
                    capability_id,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    agent_subject,
                    group_limit as i64
                ],
                |row| {
                    Ok(AgentAnalyticsRow {
                        subject_key: row.get(0)?,
                        metrics: ReceiptAnalyticsMetrics::from_raw(
                            row.get::<_, i64>(1)?.max(0) as u64,
                            row.get::<_, i64>(2)?.max(0) as u64,
                            row.get::<_, i64>(3)?.max(0) as u64,
                            row.get::<_, i64>(4)?.max(0) as u64,
                            row.get::<_, i64>(5)?.max(0) as u64,
                            row.get::<_, i64>(6)?.max(0) as u64,
                            row.get::<_, i64>(7)?.max(0) as u64,
                        ),
                    })
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;

        let by_tool_sql = r#"
            SELECT
                r.tool_server,
                r.tool_name,
                COUNT(*) AS total_receipts,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'allow' THEN 1 ELSE 0 END), 0) AS allow_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'deny' THEN 1 ELSE 0 END), 0) AS deny_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'cancelled' THEN 1 ELSE 0 END), 0) AS cancelled_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'incomplete' THEN 1 ELSE 0 END), 0) AS incomplete_count,
                COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, '$.metadata.financial.cost_charged'), 0) AS INTEGER)), 0) AS total_cost_charged,
                COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, '$.metadata.financial.attempted_cost'), 0) AS INTEGER)), 0) AS total_attempted_cost
            FROM arc_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
            GROUP BY r.tool_server, r.tool_name
            ORDER BY total_receipts DESC, r.tool_server ASC, r.tool_name ASC
            LIMIT ?7
        "#;
        let by_tool = self
            .connection
            .prepare(by_tool_sql)?
            .query_map(
                params![
                    capability_id,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    agent_subject,
                    group_limit as i64
                ],
                |row| {
                    Ok(ToolAnalyticsRow {
                        tool_server: row.get(0)?,
                        tool_name: row.get(1)?,
                        metrics: ReceiptAnalyticsMetrics::from_raw(
                            row.get::<_, i64>(2)?.max(0) as u64,
                            row.get::<_, i64>(3)?.max(0) as u64,
                            row.get::<_, i64>(4)?.max(0) as u64,
                            row.get::<_, i64>(5)?.max(0) as u64,
                            row.get::<_, i64>(6)?.max(0) as u64,
                            row.get::<_, i64>(7)?.max(0) as u64,
                            row.get::<_, i64>(8)?.max(0) as u64,
                        ),
                    })
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;

        let by_time_sql = r#"
            SELECT
                CAST((r.timestamp / ?7) * ?7 AS INTEGER) AS bucket_start,
                COUNT(*) AS total_receipts,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'allow' THEN 1 ELSE 0 END), 0) AS allow_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'deny' THEN 1 ELSE 0 END), 0) AS deny_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'cancelled' THEN 1 ELSE 0 END), 0) AS cancelled_count,
                COALESCE(SUM(CASE WHEN r.decision_kind = 'incomplete' THEN 1 ELSE 0 END), 0) AS incomplete_count,
                COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, '$.metadata.financial.cost_charged'), 0) AS INTEGER)), 0) AS total_cost_charged,
                COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, '$.metadata.financial.attempted_cost'), 0) AS INTEGER)), 0) AS total_attempted_cost
            FROM arc_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
            GROUP BY bucket_start
            ORDER BY bucket_start ASC
            LIMIT ?8
        "#;
        let by_time = self
            .connection
            .prepare(by_time_sql)?
            .query_map(
                params![
                    capability_id,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    agent_subject,
                    bucket_width,
                    group_limit as i64
                ],
                |row| {
                    let bucket_start = row.get::<_, i64>(0)?.max(0) as u64;
                    Ok(TimeAnalyticsRow {
                        bucket_start,
                        bucket_end: bucket_start
                            .saturating_add(bucket_width.max(1) as u64)
                            .saturating_sub(1),
                        metrics: ReceiptAnalyticsMetrics::from_raw(
                            row.get::<_, i64>(1)?.max(0) as u64,
                            row.get::<_, i64>(2)?.max(0) as u64,
                            row.get::<_, i64>(3)?.max(0) as u64,
                            row.get::<_, i64>(4)?.max(0) as u64,
                            row.get::<_, i64>(5)?.max(0) as u64,
                            row.get::<_, i64>(6)?.max(0) as u64,
                            row.get::<_, i64>(7)?.max(0) as u64,
                        ),
                    })
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(ReceiptAnalyticsResponse {
            summary,
            by_agent,
            by_tool,
            by_time,
        })
    }

    pub fn query_cost_attribution_report(
        &self,
        query: &CostAttributionQuery,
    ) -> Result<CostAttributionReport, ReceiptStoreError> {
        let limit = query
            .limit
            .unwrap_or(100)
            .clamp(1, MAX_COST_ATTRIBUTION_LIMIT);
        let capability_id = query.capability_id.as_deref();
        let tool_server = query.tool_server.as_deref();
        let tool_name = query.tool_name.as_deref();
        let since = query.since.map(|value| value as i64);
        let until = query.until.map(|value| value as i64);
        let agent_subject = query.agent_subject.as_deref();

        let count_sql = r#"
            SELECT COUNT(*)
            FROM arc_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
              AND json_type(r.raw_json, '$.metadata.financial') = 'object'
        "#;

        let matching_receipts = self
            .connection
            .query_row(
                count_sql,
                params![
                    capability_id,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    agent_subject
                ],
                |row| row.get::<_, i64>(0),
            )
            .map(|value| value.max(0) as u64)?;

        let data_sql = r#"
            SELECT r.seq, r.raw_json
            FROM arc_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
              AND json_type(r.raw_json, '$.metadata.financial') = 'object'
            ORDER BY r.seq ASC
        "#;

        let rows = self
            .connection
            .prepare(data_sql)?
            .query_map(
                params![
                    capability_id,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    agent_subject
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?.max(0) as u64,
                        row.get::<_, String>(1)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;

        let mut receipts = Vec::with_capacity(rows.len().min(limit));
        let mut by_root = BTreeMap::<String, RootAggregate>::new();
        let mut by_leaf = BTreeMap::<(String, String), LeafAggregate>::new();
        let mut distinct_roots = BTreeSet::new();
        let mut distinct_leaves = BTreeSet::new();
        let mut total_cost_charged = 0_u64;
        let mut total_attempted_cost = 0_u64;
        let mut max_delegation_depth = 0_u64;
        let mut lineage_gap_count = 0_u64;

        for (seq, raw_json) in rows {
            let receipt: ArcReceipt = serde_json::from_str(&raw_json)?;
            let Some(financial) = extract_financial_metadata(&receipt) else {
                continue;
            };
            let attribution = extract_receipt_attribution(&receipt);
            let chain_snapshots = self
                .get_combined_delegation_chain(&receipt.capability_id)
                .unwrap_or_default();
            let lineage_complete = chain_is_complete(&receipt.capability_id, &chain_snapshots);
            if !lineage_complete {
                lineage_gap_count = lineage_gap_count.saturating_add(1);
            }

            let chain = chain_snapshots
                .iter()
                .map(|snapshot| CostAttributionChainHop {
                    capability_id: snapshot.capability_id.clone(),
                    subject_key: snapshot.subject_key.clone(),
                    issuer_key: snapshot.issuer_key.clone(),
                    delegation_depth: snapshot.delegation_depth,
                    parent_capability_id: snapshot.parent_capability_id.clone(),
                })
                .collect::<Vec<_>>();

            let root_subject_key = chain_snapshots
                .first()
                .map(|snapshot| snapshot.subject_key.clone())
                .or_else(|| Some(financial.root_budget_holder.clone()));
            let leaf_subject_key = attribution.subject_key.clone().or_else(|| {
                chain_snapshots
                    .last()
                    .map(|snapshot| snapshot.subject_key.clone())
            });
            let attempted_cost = financial.attempted_cost.unwrap_or(0);
            let decision = decision_kind(&receipt.decision).to_string();

            total_cost_charged = total_cost_charged.saturating_add(financial.cost_charged);
            total_attempted_cost = total_attempted_cost.saturating_add(attempted_cost);
            max_delegation_depth = max_delegation_depth.max(financial.delegation_depth as u64);

            if let Some(root_key) = root_subject_key.clone() {
                distinct_roots.insert(root_key.clone());
                let root_entry = by_root.entry(root_key.clone()).or_default();
                root_entry.receipt_count = root_entry.receipt_count.saturating_add(1);
                root_entry.total_cost_charged = root_entry
                    .total_cost_charged
                    .saturating_add(financial.cost_charged);
                root_entry.total_attempted_cost = root_entry
                    .total_attempted_cost
                    .saturating_add(attempted_cost);
                root_entry.max_delegation_depth = root_entry
                    .max_delegation_depth
                    .max(financial.delegation_depth as u64);

                if let Some(leaf_key) = leaf_subject_key.clone() {
                    root_entry.leaf_subjects.insert(leaf_key.clone());
                    let leaf_entry = by_leaf.entry((root_key, leaf_key)).or_default();
                    leaf_entry.receipt_count = leaf_entry.receipt_count.saturating_add(1);
                    leaf_entry.total_cost_charged = leaf_entry
                        .total_cost_charged
                        .saturating_add(financial.cost_charged);
                    leaf_entry.total_attempted_cost = leaf_entry
                        .total_attempted_cost
                        .saturating_add(attempted_cost);
                    leaf_entry.max_delegation_depth = leaf_entry
                        .max_delegation_depth
                        .max(financial.delegation_depth as u64);
                }
            }

            if let Some(leaf_key) = leaf_subject_key.clone() {
                distinct_leaves.insert(leaf_key);
            }

            if receipts.len() < limit {
                receipts.push(CostAttributionReceiptRow {
                    seq,
                    receipt_id: receipt.id.clone(),
                    timestamp: receipt.timestamp,
                    capability_id: receipt.capability_id.clone(),
                    tool_server: receipt.tool_server.clone(),
                    tool_name: receipt.tool_name.clone(),
                    decision_kind: decision,
                    root_subject_key,
                    leaf_subject_key,
                    grant_index: Some(financial.grant_index),
                    delegation_depth: financial.delegation_depth as u64,
                    cost_charged: financial.cost_charged,
                    attempted_cost: financial.attempted_cost,
                    currency: financial.currency.clone(),
                    budget_total: Some(financial.budget_total),
                    budget_remaining: Some(financial.budget_remaining),
                    settlement_status: Some(financial.settlement_status),
                    payment_reference: financial.payment_reference.clone(),
                    lineage_complete,
                    chain,
                });
            }
        }

        let mut by_root = by_root
            .into_iter()
            .map(|(root_subject_key, aggregate)| RootCostAttributionRow {
                root_subject_key,
                receipt_count: aggregate.receipt_count,
                total_cost_charged: aggregate.total_cost_charged,
                total_attempted_cost: aggregate.total_attempted_cost,
                distinct_leaf_subjects: aggregate.leaf_subjects.len() as u64,
                max_delegation_depth: aggregate.max_delegation_depth,
            })
            .collect::<Vec<_>>();
        by_root.sort_by(|left, right| {
            right
                .total_cost_charged
                .cmp(&left.total_cost_charged)
                .then_with(|| right.receipt_count.cmp(&left.receipt_count))
                .then_with(|| left.root_subject_key.cmp(&right.root_subject_key))
        });

        let mut by_leaf = by_leaf
            .into_iter()
            .map(
                |((root_subject_key, leaf_subject_key), aggregate)| LeafCostAttributionRow {
                    root_subject_key,
                    leaf_subject_key,
                    receipt_count: aggregate.receipt_count,
                    total_cost_charged: aggregate.total_cost_charged,
                    total_attempted_cost: aggregate.total_attempted_cost,
                    max_delegation_depth: aggregate.max_delegation_depth,
                },
            )
            .collect::<Vec<_>>();
        by_leaf.sort_by(|left, right| {
            right
                .total_cost_charged
                .cmp(&left.total_cost_charged)
                .then_with(|| right.receipt_count.cmp(&left.receipt_count))
                .then_with(|| left.root_subject_key.cmp(&right.root_subject_key))
                .then_with(|| left.leaf_subject_key.cmp(&right.leaf_subject_key))
        });

        Ok(CostAttributionReport {
            summary: CostAttributionSummary {
                matching_receipts,
                returned_receipts: receipts.len() as u64,
                total_cost_charged,
                total_attempted_cost,
                max_delegation_depth,
                distinct_root_subjects: distinct_roots.len() as u64,
                distinct_leaf_subjects: distinct_leaves.len() as u64,
                lineage_gap_count,
                truncated: matching_receipts > receipts.len() as u64,
            },
            by_root,
            by_leaf,
            receipts,
        })
    }

    pub fn query_shared_evidence_report(
        &self,
        query: &SharedEvidenceQuery,
    ) -> Result<SharedEvidenceReferenceReport, ReceiptStoreError> {
        let limit = query.limit_or_default();
        let capability_id = query.capability_id.as_deref();
        let tool_server = query.tool_server.as_deref();
        let tool_name = query.tool_name.as_deref();
        let since = query.since.map(|value| value as i64);
        let until = query.until.map(|value| value as i64);
        let agent_subject = query.agent_subject.as_deref();
        let issuer = query.issuer.as_deref();
        let partner = query.partner.as_deref();

        let rows = self
            .connection
            .prepare(
                r#"
                SELECT r.receipt_id, r.timestamp, r.capability_id, r.decision_kind
                FROM arc_tool_receipts r
                LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
                WHERE (?1 IS NULL OR r.capability_id = ?1)
                  AND (?2 IS NULL OR r.tool_server = ?2)
                  AND (?3 IS NULL OR r.tool_name = ?3)
                  AND (?4 IS NULL OR r.timestamp >= ?4)
                  AND (?5 IS NULL OR r.timestamp <= ?5)
                  AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
                ORDER BY r.seq ASC
                "#,
            )?
            .query_map(
                params![
                    capability_id,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    agent_subject
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?.max(0) as u64,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;

        let mut share_cache = BTreeMap::<String, Option<FederatedEvidenceShareSummary>>::new();
        let mut references = BTreeMap::<(String, String), SharedEvidenceReferenceRow>::new();
        let mut matched_local_receipts = BTreeSet::<String>::new();

        for (receipt_id, timestamp, local_capability_id, decision) in rows {
            let chain = self.get_combined_delegation_chain(&local_capability_id)?;
            if chain.is_empty() {
                continue;
            }

            let mut matched_this_receipt = false;
            for (index, snapshot) in chain.iter().enumerate() {
                let share = match share_cache.get(&snapshot.capability_id) {
                    Some(cached) => cached.clone(),
                    None => {
                        let loaded = self
                            .get_federated_share_for_capability(&snapshot.capability_id)?
                            .map(|(share, _)| share);
                        share_cache.insert(snapshot.capability_id.clone(), loaded.clone());
                        loaded
                    }
                };
                let Some(share) = share else {
                    continue;
                };
                if issuer.is_some_and(|expected| share.issuer != expected) {
                    continue;
                }
                if partner.is_some_and(|expected| share.partner != expected) {
                    continue;
                }

                let local_anchor_capability_id =
                    chain.iter().skip(index + 1).find_map(|candidate| {
                        match share_cache.get(&candidate.capability_id) {
                            Some(Some(_)) => None,
                            Some(None) => Some(candidate.capability_id.clone()),
                            None => {
                                let loaded = self
                                    .get_federated_share_for_capability(&candidate.capability_id)
                                    .ok()
                                    .and_then(|value| value.map(|(share, _)| share));
                                share_cache.insert(candidate.capability_id.clone(), loaded.clone());
                                if loaded.is_some() {
                                    None
                                } else {
                                    Some(candidate.capability_id.clone())
                                }
                            }
                        }
                    });

                let key = (share.share_id.clone(), snapshot.capability_id.clone());
                let entry = references
                    .entry(key)
                    .or_insert_with(|| SharedEvidenceReferenceRow {
                        share: share.clone(),
                        capability_id: snapshot.capability_id.clone(),
                        subject_key: snapshot.subject_key.clone(),
                        issuer_key: snapshot.issuer_key.clone(),
                        delegation_depth: snapshot.delegation_depth,
                        parent_capability_id: snapshot.parent_capability_id.clone(),
                        local_anchor_capability_id: local_anchor_capability_id.clone(),
                        matched_local_receipts: 0,
                        allow_count: 0,
                        deny_count: 0,
                        cancelled_count: 0,
                        incomplete_count: 0,
                        first_seen: Some(timestamp),
                        last_seen: Some(timestamp),
                    });

                entry.local_anchor_capability_id = entry
                    .local_anchor_capability_id
                    .clone()
                    .or(local_anchor_capability_id);
                entry.matched_local_receipts = entry.matched_local_receipts.saturating_add(1);
                entry.first_seen = Some(
                    entry
                        .first_seen
                        .map_or(timestamp, |value| value.min(timestamp)),
                );
                entry.last_seen = Some(
                    entry
                        .last_seen
                        .map_or(timestamp, |value| value.max(timestamp)),
                );
                match decision.as_str() {
                    "allow" => entry.allow_count = entry.allow_count.saturating_add(1),
                    "deny" => entry.deny_count = entry.deny_count.saturating_add(1),
                    "cancelled" => entry.cancelled_count = entry.cancelled_count.saturating_add(1),
                    _ => entry.incomplete_count = entry.incomplete_count.saturating_add(1),
                }
                matched_this_receipt = true;
            }

            if matched_this_receipt {
                matched_local_receipts.insert(receipt_id);
            }
        }

        let mut returned_references = references.into_values().collect::<Vec<_>>();
        returned_references.sort_by(|left, right| {
            right
                .matched_local_receipts
                .cmp(&left.matched_local_receipts)
                .then_with(|| right.last_seen.cmp(&left.last_seen))
                .then_with(|| right.share.imported_at.cmp(&left.share.imported_at))
                .then_with(|| left.share.share_id.cmp(&right.share.share_id))
                .then_with(|| left.capability_id.cmp(&right.capability_id))
        });

        let mut distinct_shares = BTreeMap::<String, FederatedEvidenceShareSummary>::new();
        let mut distinct_remote_subjects = BTreeSet::<String>::new();
        for reference in &returned_references {
            distinct_shares
                .entry(reference.share.share_id.clone())
                .or_insert_with(|| reference.share.clone());
            distinct_remote_subjects.insert(reference.subject_key.clone());
        }

        let matching_references = returned_references.len() as u64;
        let truncated = returned_references.len() > limit;
        if truncated {
            returned_references.truncate(limit);
        }

        Ok(SharedEvidenceReferenceReport {
            summary: SharedEvidenceReferenceSummary {
                matching_shares: distinct_shares.len() as u64,
                matching_references,
                matching_local_receipts: matched_local_receipts.len() as u64,
                remote_tool_receipts: distinct_shares
                    .values()
                    .map(|share| share.tool_receipts)
                    .sum(),
                remote_lineage_records: distinct_shares
                    .values()
                    .map(|share| share.capability_lineage)
                    .sum(),
                distinct_remote_subjects: distinct_remote_subjects.len() as u64,
                proof_required_shares: distinct_shares
                    .values()
                    .filter(|share| share.require_proofs)
                    .count() as u64,
                truncated,
            },
            references: returned_references,
        })
    }

    pub fn query_compliance_report(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<ComplianceReport, ReceiptStoreError> {
        let capability_id = query.capability_id.as_deref();
        let tool_server = query.tool_server.as_deref();
        let tool_name = query.tool_name.as_deref();
        let since = query.since.map(|value| value as i64);
        let until = query.until.map(|value| value as i64);
        let agent_subject = query.agent_subject.as_deref();

        let summary_sql = r#"
            SELECT
                COUNT(*) AS matching_receipts,
                COALESCE(SUM(
                    CASE
                        WHEN EXISTS(
                            SELECT 1
                            FROM kernel_checkpoints kc
                            WHERE r.seq BETWEEN kc.batch_start_seq AND kc.batch_end_seq
                        ) THEN 1
                        ELSE 0
                    END
                ), 0) AS evidence_ready_receipts,
                COALESCE(SUM(CASE WHEN cl.capability_id IS NOT NULL THEN 1 ELSE 0 END), 0) AS lineage_covered_receipts,
                COALESCE(SUM(
                    CASE
                        WHEN json_extract(r.raw_json, '$.metadata.financial.settlement_status') = 'pending' THEN 1
                        ELSE 0
                    END
                ), 0) AS pending_settlement_receipts,
                COALESCE(SUM(
                    CASE
                        WHEN json_extract(r.raw_json, '$.metadata.financial.settlement_status') = 'failed' THEN 1
                        ELSE 0
                    END
                ), 0) AS failed_settlement_receipts
            FROM arc_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
        "#;

        let (
            matching_receipts,
            evidence_ready_receipts,
            lineage_covered_receipts,
            pending_settlement_receipts,
            failed_settlement_receipts,
        ) = self.connection.query_row(
            summary_sql,
            params![
                capability_id,
                tool_server,
                tool_name,
                since,
                until,
                agent_subject
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?.max(0) as u64,
                    row.get::<_, i64>(1)?.max(0) as u64,
                    row.get::<_, i64>(2)?.max(0) as u64,
                    row.get::<_, i64>(3)?.max(0) as u64,
                    row.get::<_, i64>(4)?.max(0) as u64,
                ))
            },
        )?;

        let uncheckpointed_receipts = matching_receipts.saturating_sub(evidence_ready_receipts);
        let lineage_gap_receipts = matching_receipts.saturating_sub(lineage_covered_receipts);
        let export_query = query.to_evidence_export_query();

        Ok(ComplianceReport {
            matching_receipts,
            evidence_ready_receipts,
            uncheckpointed_receipts,
            checkpoint_coverage_rate: ratio_option(evidence_ready_receipts, matching_receipts),
            lineage_covered_receipts,
            lineage_gap_receipts,
            lineage_coverage_rate: ratio_option(lineage_covered_receipts, matching_receipts),
            pending_settlement_receipts,
            failed_settlement_receipts,
            direct_evidence_export_supported: query.direct_evidence_export_supported(),
            child_receipt_scope: export_query.child_receipt_scope(),
            proofs_complete: uncheckpointed_receipts == 0,
            export_query: export_query.clone(),
            export_scope_note: compliance_export_scope_note(query, &export_query),
        })
    }

    pub fn upsert_settlement_reconciliation(
        &self,
        receipt_id: &str,
        reconciliation_state: SettlementReconciliationState,
        note: Option<&str>,
    ) -> Result<i64, ReceiptStoreError> {
        let exists = self
            .connection
            .query_row(
                "SELECT 1 FROM arc_tool_receipts WHERE receipt_id = ?1",
                params![receipt_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        if exists.is_none() {
            return Err(ReceiptStoreError::NotFound(format!(
                "receipt {receipt_id} does not exist"
            )));
        }

        let updated_at = unix_timestamp_now_i64();
        self.connection.execute(
            r#"
            INSERT INTO settlement_reconciliations (
                receipt_id,
                reconciliation_state,
                note,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(receipt_id) DO UPDATE SET
                reconciliation_state = excluded.reconciliation_state,
                note = excluded.note,
                updated_at = excluded.updated_at
            "#,
            params![
                receipt_id,
                settlement_reconciliation_state_text(reconciliation_state),
                note,
                updated_at
            ],
        )?;

        Ok(updated_at)
    }

    pub fn upsert_metered_billing_reconciliation(
        &self,
        receipt_id: &str,
        evidence: &MeteredBillingEvidenceRecord,
        reconciliation_state: MeteredBillingReconciliationState,
        note: Option<&str>,
    ) -> Result<i64, ReceiptStoreError> {
        let raw_json = self
            .connection
            .query_row(
                "SELECT raw_json FROM arc_tool_receipts WHERE receipt_id = ?1",
                params![receipt_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!("receipt {receipt_id} does not exist"))
            })?;
        let receipt: ArcReceipt = serde_json::from_str(&raw_json)?;
        let governed = extract_governed_transaction_metadata(&receipt).ok_or_else(|| {
            ReceiptStoreError::Conflict(format!(
                "receipt {receipt_id} does not carry governed transaction metadata"
            ))
        })?;
        if governed.metered_billing.is_none() {
            return Err(ReceiptStoreError::Conflict(format!(
                "receipt {receipt_id} does not carry metered billing context"
            )));
        }

        let existing_receipt = self
            .connection
            .query_row(
                r#"
                SELECT receipt_id
                FROM metered_billing_reconciliations
                WHERE adapter_kind = ?1 AND evidence_id = ?2
                "#,
                params![
                    &evidence.usage_evidence.evidence_kind,
                    &evidence.usage_evidence.evidence_id
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(existing_receipt) = existing_receipt {
            if existing_receipt != receipt_id {
                return Err(ReceiptStoreError::Conflict(format!(
                    "metered billing evidence {}/{} is already attached to receipt {}",
                    evidence.usage_evidence.evidence_kind,
                    evidence.usage_evidence.evidence_id,
                    existing_receipt
                )));
            }
        }

        let updated_at = unix_timestamp_now_i64();
        self.connection.execute(
            r#"
            INSERT INTO metered_billing_reconciliations (
                receipt_id,
                adapter_kind,
                evidence_id,
                observed_units,
                billed_cost_units,
                billed_cost_currency,
                evidence_sha256,
                recorded_at,
                reconciliation_state,
                note,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            ON CONFLICT(receipt_id) DO UPDATE SET
                adapter_kind = excluded.adapter_kind,
                evidence_id = excluded.evidence_id,
                observed_units = excluded.observed_units,
                billed_cost_units = excluded.billed_cost_units,
                billed_cost_currency = excluded.billed_cost_currency,
                evidence_sha256 = excluded.evidence_sha256,
                recorded_at = excluded.recorded_at,
                reconciliation_state = excluded.reconciliation_state,
                note = excluded.note,
                updated_at = excluded.updated_at
            "#,
            params![
                receipt_id,
                &evidence.usage_evidence.evidence_kind,
                &evidence.usage_evidence.evidence_id,
                evidence.usage_evidence.observed_units as i64,
                evidence.billed_cost.units as i64,
                &evidence.billed_cost.currency,
                evidence.usage_evidence.evidence_sha256.as_deref(),
                evidence.recorded_at as i64,
                metered_billing_reconciliation_state_text(reconciliation_state),
                note,
                updated_at
            ],
        )?;

        Ok(updated_at)
    }

    pub fn query_metered_billing_reconciliation_report(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<MeteredBillingReconciliationReport, ReceiptStoreError> {
        let capability_id = query.capability_id.as_deref();
        let tool_server = query.tool_server.as_deref();
        let tool_name = query.tool_name.as_deref();
        let since = query.since.map(|value| value as i64);
        let until = query.until.map(|value| value as i64);
        let agent_subject = query.agent_subject.as_deref();
        let row_limit = query.metered_limit_or_default();

        let summary = self.query_metered_billing_summary(query)?;

        let rows_sql = r#"
            SELECT
                r.raw_json,
                COALESCE(r.subject_key, cl.subject_key),
                mbr.adapter_kind,
                mbr.evidence_id,
                mbr.observed_units,
                mbr.billed_cost_units,
                mbr.billed_cost_currency,
                mbr.evidence_sha256,
                mbr.recorded_at,
                COALESCE(mbr.reconciliation_state, 'open'),
                mbr.note,
                mbr.updated_at
            FROM arc_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            LEFT JOIN metered_billing_reconciliations mbr ON r.receipt_id = mbr.receipt_id
            WHERE json_type(r.raw_json, '$.metadata.governed_transaction.metered_billing') = 'object'
              AND (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
            ORDER BY r.timestamp DESC, r.seq DESC
            LIMIT ?7
        "#;

        let mut stmt = self.connection.prepare(rows_sql)?;
        let rows = stmt.query_map(
            params![
                capability_id,
                tool_server,
                tool_name,
                since,
                until,
                agent_subject,
                row_limit as i64
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, Option<i64>>(11)?,
                ))
            },
        )?;

        let mut receipts = Vec::new();
        for row in rows {
            let (
                raw_json,
                subject_key,
                adapter_kind,
                evidence_id,
                observed_units,
                billed_cost_units,
                billed_cost_currency,
                evidence_sha256,
                recorded_at,
                reconciliation_state_text,
                note,
                updated_at,
            ) = row?;
            let receipt: ArcReceipt = serde_json::from_str(&raw_json)?;
            let governed = extract_governed_transaction_metadata(&receipt).ok_or_else(|| {
                ReceiptStoreError::Canonical(format!(
                    "receipt {} is missing governed transaction metadata",
                    receipt.id
                ))
            })?;
            let metered = governed.metered_billing.ok_or_else(|| {
                ReceiptStoreError::Canonical(format!(
                    "receipt {} is missing metered billing metadata",
                    receipt.id
                ))
            })?;
            let financial = extract_financial_metadata(&receipt);
            let evidence = metered_billing_evidence_record_from_columns(
                adapter_kind,
                evidence_id,
                observed_units,
                billed_cost_units,
                billed_cost_currency,
                evidence_sha256,
                recorded_at,
            );
            let reconciliation_state =
                parse_metered_billing_reconciliation_state(&reconciliation_state_text)?;
            let analysis = analyze_metered_billing_reconciliation(
                &metered,
                financial.as_ref(),
                evidence.as_ref(),
                reconciliation_state,
            );

            receipts.push(MeteredBillingReconciliationRow {
                receipt_id: receipt.id,
                timestamp: receipt.timestamp,
                capability_id: receipt.capability_id,
                subject_key,
                tool_server: receipt.tool_server,
                tool_name: receipt.tool_name,
                settlement_mode: metered.settlement_mode,
                provider: metered.quote.provider.clone(),
                quote_id: metered.quote.quote_id.clone(),
                billing_unit: metered.quote.billing_unit.clone(),
                quoted_units: metered.quote.quoted_units,
                quoted_cost: metered.quote.quoted_cost.clone(),
                max_billed_units: metered.max_billed_units,
                financial_cost_charged: financial.as_ref().map(|value| value.cost_charged),
                financial_currency: financial.as_ref().map(|value| value.currency.clone()),
                evidence,
                reconciliation_state,
                action_required: analysis.action_required,
                evidence_missing: analysis.evidence_missing,
                exceeds_quoted_units: analysis.exceeds_quoted_units,
                exceeds_max_billed_units: analysis.exceeds_max_billed_units,
                exceeds_quoted_cost: analysis.exceeds_quoted_cost,
                financial_mismatch: analysis.financial_mismatch,
                note,
                updated_at: updated_at.map(|value| value.max(0) as u64),
            });
        }

        Ok(MeteredBillingReconciliationReport {
            summary: MeteredBillingReconciliationSummary {
                matching_receipts: summary.metered_receipts,
                returned_receipts: receipts.len() as u64,
                evidence_attached_receipts: summary.evidence_attached_receipts,
                missing_evidence_receipts: summary.missing_evidence_receipts,
                over_quoted_units_receipts: summary.over_quoted_units_receipts,
                over_max_billed_units_receipts: summary.over_max_billed_units_receipts,
                over_quoted_cost_receipts: summary.over_quoted_cost_receipts,
                financial_mismatch_receipts: summary.financial_mismatch_receipts,
                actionable_receipts: summary.actionable_receipts,
                reconciled_receipts: summary.reconciled_receipts,
                truncated: summary.metered_receipts > receipts.len() as u64,
            },
            receipts,
        })
    }

    pub fn query_settlement_reconciliation_report(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<SettlementReconciliationReport, ReceiptStoreError> {
        let capability_id = query.capability_id.as_deref();
        let tool_server = query.tool_server.as_deref();
        let tool_name = query.tool_name.as_deref();
        let since = query.since.map(|value| value as i64);
        let until = query.until.map(|value| value as i64);
        let agent_subject = query.agent_subject.as_deref();
        let row_limit = query.settlement_limit_or_default();

        let summary_sql = r#"
            SELECT
                COUNT(*) AS matching_receipts,
                COALESCE(SUM(
                    CASE
                        WHEN json_extract(r.raw_json, '$.metadata.financial.settlement_status') = 'pending' THEN 1
                        ELSE 0
                    END
                ), 0) AS pending_receipts,
                COALESCE(SUM(
                    CASE
                        WHEN json_extract(r.raw_json, '$.metadata.financial.settlement_status') = 'failed' THEN 1
                        ELSE 0
                    END
                ), 0) AS failed_receipts,
                COALESCE(SUM(
                    CASE
                        WHEN COALESCE(sr.reconciliation_state, 'open') NOT IN ('reconciled', 'ignored') THEN 1
                        ELSE 0
                    END
                ), 0) AS actionable_receipts,
                COALESCE(SUM(
                    CASE
                        WHEN COALESCE(sr.reconciliation_state, 'open') = 'reconciled' THEN 1
                        ELSE 0
                    END
                ), 0) AS reconciled_receipts
            FROM arc_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            LEFT JOIN settlement_reconciliations sr ON r.receipt_id = sr.receipt_id
            WHERE json_extract(r.raw_json, '$.metadata.financial.settlement_status') IN ('pending', 'failed')
              AND (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
        "#;

        let (
            matching_receipts,
            pending_receipts,
            failed_receipts,
            actionable_receipts,
            reconciled_receipts,
        ) = self.connection.query_row(
            summary_sql,
            params![
                capability_id,
                tool_server,
                tool_name,
                since,
                until,
                agent_subject
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?.max(0) as u64,
                    row.get::<_, i64>(1)?.max(0) as u64,
                    row.get::<_, i64>(2)?.max(0) as u64,
                    row.get::<_, i64>(3)?.max(0) as u64,
                    row.get::<_, i64>(4)?.max(0) as u64,
                ))
            },
        )?;

        let rows_sql = r#"
            SELECT
                r.receipt_id,
                r.timestamp,
                r.capability_id,
                COALESCE(r.subject_key, cl.subject_key),
                r.tool_server,
                r.tool_name,
                json_extract(r.raw_json, '$.metadata.financial.payment_reference'),
                json_extract(r.raw_json, '$.metadata.financial.settlement_status'),
                CAST(json_extract(r.raw_json, '$.metadata.financial.cost_charged') AS INTEGER),
                json_extract(r.raw_json, '$.metadata.financial.currency'),
                COALESCE(sr.reconciliation_state, 'open'),
                sr.note,
                sr.updated_at
            FROM arc_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            LEFT JOIN settlement_reconciliations sr ON r.receipt_id = sr.receipt_id
            WHERE json_extract(r.raw_json, '$.metadata.financial.settlement_status') IN ('pending', 'failed')
              AND (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
            ORDER BY r.timestamp DESC, r.seq DESC
            LIMIT ?7
        "#;

        let mut stmt = self.connection.prepare(rows_sql)?;
        let rows = stmt.query_map(
            params![
                capability_id,
                tool_server,
                tool_name,
                since,
                until,
                agent_subject,
                row_limit as i64
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<i64>>(12)?,
                ))
            },
        )?;

        let mut receipts = Vec::new();
        for row in rows {
            let (
                receipt_id,
                timestamp,
                capability_id,
                subject_key,
                tool_server,
                tool_name,
                payment_reference,
                settlement_status_text,
                cost_charged,
                currency,
                reconciliation_state_text,
                note,
                updated_at,
            ) = row?;
            let settlement_status = parse_settlement_status(&settlement_status_text)?;
            let reconciliation_state =
                parse_settlement_reconciliation_state(&reconciliation_state_text)?;
            let action_required = settlement_reconciliation_action_required(
                settlement_status.clone(),
                reconciliation_state,
            );
            receipts.push(SettlementReconciliationRow {
                receipt_id,
                timestamp: timestamp.max(0) as u64,
                capability_id,
                subject_key,
                tool_server,
                tool_name,
                payment_reference,
                settlement_status,
                cost_charged: cost_charged.map(|value| value.max(0) as u64),
                currency,
                reconciliation_state,
                action_required,
                note,
                updated_at: updated_at.map(|value| value.max(0) as u64),
            });
        }

        Ok(SettlementReconciliationReport {
            summary: SettlementReconciliationSummary {
                matching_receipts,
                returned_receipts: receipts.len() as u64,
                pending_receipts,
                failed_receipts,
                actionable_receipts,
                reconciled_receipts,
                truncated: matching_receipts > receipts.len() as u64,
            },
            receipts,
        })
    }

    pub fn query_authorization_context_report(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<AuthorizationContextReport, ReceiptStoreError> {
        let capability_id = query.capability_id.as_deref();
        let tool_server = query.tool_server.as_deref();
        let tool_name = query.tool_name.as_deref();
        let since = query.since.map(|value| value as i64);
        let until = query.until.map(|value| value as i64);
        let agent_subject = query.agent_subject.as_deref();
        let row_limit = query.authorization_limit_or_default();

        let summary_sql = r#"
            SELECT
                COUNT(*),
                COALESCE(SUM(
                    CASE
                        WHEN json_type(r.raw_json, '$.metadata.governed_transaction.approval') = 'object' THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN json_extract(r.raw_json, '$.metadata.governed_transaction.approval.approved') = 1 THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN json_type(r.raw_json, '$.metadata.governed_transaction.commerce') = 'object' THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN json_type(r.raw_json, '$.metadata.governed_transaction.metered_billing') = 'object' THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN json_type(r.raw_json, '$.metadata.governed_transaction.runtime_assurance') = 'object' THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN json_type(r.raw_json, '$.metadata.governed_transaction.call_chain') = 'object' THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN json_type(r.raw_json, '$.metadata.governed_transaction.max_amount') = 'object' THEN 1
                        ELSE 0
                    END
                ), 0)
            FROM arc_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE json_type(r.raw_json, '$.metadata.governed_transaction') = 'object'
              AND (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
        "#;

        let (
            matching_receipts,
            approval_receipts,
            approved_receipts,
            commerce_receipts,
            metered_billing_receipts,
            runtime_assurance_receipts,
            call_chain_receipts,
            max_amount_receipts,
        ) = self.connection.query_row(
            summary_sql,
            params![
                capability_id,
                tool_server,
                tool_name,
                since,
                until,
                agent_subject
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?.max(0) as u64,
                    row.get::<_, i64>(1)?.max(0) as u64,
                    row.get::<_, i64>(2)?.max(0) as u64,
                    row.get::<_, i64>(3)?.max(0) as u64,
                    row.get::<_, i64>(4)?.max(0) as u64,
                    row.get::<_, i64>(5)?.max(0) as u64,
                    row.get::<_, i64>(6)?.max(0) as u64,
                    row.get::<_, i64>(7)?.max(0) as u64,
                ))
            },
        )?;

        let rows_sql = r#"
            SELECT
                r.raw_json,
                r.subject_key,
                r.issuer_key,
                cl.subject_key,
                cl.issuer_key,
                r.grant_index,
                cl.grants_json
            FROM arc_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE json_type(r.raw_json, '$.metadata.governed_transaction') = 'object'
              AND (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
            ORDER BY r.timestamp DESC, r.seq DESC
        "#;

        let mut stmt = self.connection.prepare(rows_sql)?;
        let rows = stmt.query_map(
            params![
                capability_id,
                tool_server,
                tool_name,
                since,
                until,
                agent_subject
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            },
        )?;

        let mut sender_bound_receipts = 0_u64;
        let mut dpop_bound_receipts = 0_u64;
        let mut runtime_assurance_bound_receipts = 0_u64;
        let mut delegated_sender_bound_receipts = 0_u64;
        let mut receipts = Vec::new();
        for row in rows {
            let (
                raw_json,
                receipt_subject_key,
                receipt_issuer_key,
                lineage_subject_key,
                lineage_issuer_key,
                persisted_grant_index,
                grants_json,
            ) = row?;
            let receipt: ArcReceipt = serde_json::from_str(&raw_json)?;
            let governed = extract_governed_transaction_metadata(&receipt).ok_or_else(|| {
                ReceiptStoreError::Canonical(format!(
                    "receipt {} is missing governed transaction metadata",
                    receipt.id
                ))
            })?;
            let attribution = extract_receipt_attribution(&receipt);
            let transaction_context =
                authorization_transaction_context_from_governed_metadata(&governed);
            let sender_constraint = derive_authorization_sender_constraint(
                &receipt.id,
                &receipt.tool_server,
                &receipt.tool_name,
                receipt_subject_key.as_deref(),
                receipt_issuer_key.as_deref(),
                lineage_subject_key.as_deref(),
                lineage_issuer_key.as_deref(),
                attribution
                    .grant_index
                    .or_else(|| persisted_grant_index.map(|value| value.max(0) as u32)),
                grants_json.as_deref(),
                &transaction_context,
            )?;

            let authorization_row = AuthorizationContextRow {
                receipt_id: receipt.id,
                timestamp: receipt.timestamp,
                capability_id: receipt.capability_id,
                subject_key: Some(sender_constraint.subject_key.clone()),
                tool_server: receipt.tool_server,
                tool_name: receipt.tool_name,
                decision: receipt.decision,
                authorization_details: authorization_details_from_governed_metadata(&governed),
                transaction_context,
                sender_constraint,
            };
            validate_arc_oauth_authorization_row(&authorization_row)?;
            sender_bound_receipts += 1;
            if authorization_row.sender_constraint.proof_required {
                dpop_bound_receipts += 1;
            }
            if authorization_row.sender_constraint.runtime_assurance_bound {
                runtime_assurance_bound_receipts += 1;
            }
            if authorization_row
                .sender_constraint
                .delegated_call_chain_bound
            {
                delegated_sender_bound_receipts += 1;
            }
            if receipts.len() < row_limit {
                receipts.push(authorization_row);
            }
        }

        Ok(AuthorizationContextReport {
            schema: ARC_OAUTH_AUTHORIZATION_CONTEXT_REPORT_SCHEMA.to_string(),
            profile: ArcOAuthAuthorizationProfile::default(),
            summary: AuthorizationContextSummary {
                matching_receipts,
                returned_receipts: receipts.len() as u64,
                approval_receipts,
                approved_receipts,
                commerce_receipts,
                metered_billing_receipts,
                runtime_assurance_receipts,
                call_chain_receipts,
                max_amount_receipts,
                sender_bound_receipts,
                dpop_bound_receipts,
                runtime_assurance_bound_receipts,
                delegated_sender_bound_receipts,
                truncated: matching_receipts > receipts.len() as u64,
            },
            receipts,
        })
    }

    pub fn authorization_profile_metadata_report(&self) -> ArcOAuthAuthorizationMetadataReport {
        ArcOAuthAuthorizationMetadataReport {
            schema: ARC_OAUTH_AUTHORIZATION_METADATA_SCHEMA.to_string(),
            generated_at: unix_now(),
            profile: ArcOAuthAuthorizationProfile::default(),
            report_schema: ARC_OAUTH_AUTHORIZATION_CONTEXT_REPORT_SCHEMA.to_string(),
            discovery: ArcOAuthAuthorizationDiscoveryMetadata {
                protected_resource_metadata_paths: vec![
                    "/.well-known/oauth-protected-resource".to_string(),
                    "/.well-known/oauth-protected-resource/mcp".to_string(),
                ],
                authorization_server_metadata_path_template:
                    "/.well-known/oauth-authorization-server/{issuer-path}".to_string(),
                discovery_informational_only: true,
            },
            support_boundary: ArcOAuthAuthorizationSupportBoundary {
                governed_receipts_authoritative: true,
                hosted_request_time_authorization_supported: true,
                resource_indicator_binding_supported: true,
                sender_constrained_projection: true,
                runtime_assurance_projection: true,
                delegated_call_chain_projection: true,
                generic_token_issuance_supported: false,
                oidc_identity_assertions_supported: false,
                mtls_transport_binding_in_profile: false,
                approval_tokens_runtime_authorization_supported: false,
                capabilities_runtime_authorization_supported: false,
                reviewer_evidence_runtime_authorization_supported: false,
            },
            example_mapping: ArcOAuthAuthorizationExampleMapping {
                authorization_detail_types: vec![
                    "type".to_string(),
                    "locations".to_string(),
                    "actions".to_string(),
                    "purpose".to_string(),
                    "maxAmount".to_string(),
                    "commerce".to_string(),
                    "meteredBilling".to_string(),
                ],
                transaction_context_fields: ArcOAuthAuthorizationProfile::default()
                    .transaction_context_fields,
                sender_constraint_fields: vec![
                    "subjectKey".to_string(),
                    "subjectKeySource".to_string(),
                    "issuerKey".to_string(),
                    "issuerKeySource".to_string(),
                    "matchedGrantIndex".to_string(),
                    "proofRequired".to_string(),
                    "proofType".to_string(),
                    "proofSchema".to_string(),
                    "runtimeAssuranceBound".to_string(),
                    "delegatedCallChainBound".to_string(),
                ],
            },
        }
    }

    pub fn query_authorization_review_pack(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<ArcOAuthAuthorizationReviewPack, ReceiptStoreError> {
        let authorization_context = self.query_authorization_context_report(query)?;
        let metadata = self.authorization_profile_metadata_report();
        let mut records = Vec::with_capacity(authorization_context.receipts.len());

        for row in authorization_context.receipts {
            let raw_json = self.connection.query_row(
                "SELECT raw_json FROM arc_tool_receipts WHERE receipt_id = ?1",
                params![row.receipt_id.as_str()],
                |db_row| db_row.get::<_, String>(0),
            )?;
            let signed_receipt: ArcReceipt = serde_json::from_str(&raw_json)?;
            let governed_transaction = extract_governed_transaction_metadata(&signed_receipt)
                .ok_or_else(|| {
                    ReceiptStoreError::Canonical(format!(
                        "receipt {} is missing governed transaction metadata",
                        signed_receipt.id
                    ))
                })?;
            records.push(ArcOAuthAuthorizationReviewPackRecord {
                receipt_id: row.receipt_id.clone(),
                capability_id: row.capability_id.clone(),
                authorization_context: row,
                governed_transaction,
                signed_receipt,
            });
        }

        Ok(ArcOAuthAuthorizationReviewPack {
            schema: ARC_OAUTH_AUTHORIZATION_REVIEW_PACK_SCHEMA.to_string(),
            generated_at: unix_now(),
            filters: query.clone(),
            metadata,
            summary: ArcOAuthAuthorizationReviewPackSummary {
                matching_receipts: authorization_context.summary.matching_receipts,
                returned_receipts: records.len() as u64,
                dpop_required_receipts: authorization_context.summary.dpop_bound_receipts,
                runtime_assurance_receipts: authorization_context
                    .summary
                    .runtime_assurance_bound_receipts,
                delegated_call_chain_receipts: authorization_context
                    .summary
                    .delegated_sender_bound_receipts,
                truncated: authorization_context.summary.truncated,
            },
            records,
        })
    }

    pub fn query_behavioral_feed_receipts(
        &self,
        query: &BehavioralFeedQuery,
    ) -> Result<
        (
            BehavioralFeedSettlementSummary,
            BehavioralFeedGovernedActionSummary,
            BehavioralFeedMeteredBillingSummary,
            BehavioralFeedReceiptSelection,
        ),
        ReceiptStoreError,
    > {
        let operator_query = query.to_operator_report_query();
        let capability_id = operator_query.capability_id.as_deref();
        let tool_server = operator_query.tool_server.as_deref();
        let tool_name = operator_query.tool_name.as_deref();
        let since = operator_query.since.map(|value| value as i64);
        let until = operator_query.until.map(|value| value as i64);
        let agent_subject = operator_query.agent_subject.as_deref();

        let summary_sql = r#"
            SELECT
                COALESCE(SUM(
                    CASE
                        WHEN COALESCE(json_extract(r.raw_json, '$.metadata.financial.settlement_status'), 'not_applicable') = 'pending' THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN COALESCE(json_extract(r.raw_json, '$.metadata.financial.settlement_status'), 'not_applicable') = 'settled' THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN COALESCE(json_extract(r.raw_json, '$.metadata.financial.settlement_status'), 'not_applicable') = 'failed' THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN COALESCE(json_extract(r.raw_json, '$.metadata.financial.settlement_status'), 'not_applicable') = 'not_applicable' THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN COALESCE(json_extract(r.raw_json, '$.metadata.financial.settlement_status'), 'not_applicable') IN ('pending', 'failed')
                         AND COALESCE(sr.reconciliation_state, 'open') NOT IN ('reconciled', 'ignored')
                        THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN COALESCE(sr.reconciliation_state, 'open') = 'reconciled' THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN json_type(r.raw_json, '$.metadata.governed_transaction') IS NOT NULL THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN json_type(r.raw_json, '$.metadata.governed_transaction.approval') IS NOT NULL THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN json_extract(r.raw_json, '$.metadata.governed_transaction.approval.approved') = 1 THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN json_type(r.raw_json, '$.metadata.governed_transaction.commerce') IS NOT NULL THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN json_type(r.raw_json, '$.metadata.governed_transaction.max_amount') IS NOT NULL THEN 1
                        ELSE 0
                    END
                ), 0)
            FROM arc_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            LEFT JOIN settlement_reconciliations sr ON r.receipt_id = sr.receipt_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
        "#;

        let (settlements, governed_actions) = self.connection.query_row(
            summary_sql,
            params![
                capability_id,
                tool_server,
                tool_name,
                since,
                until,
                agent_subject
            ],
            |row| {
                Ok((
                    BehavioralFeedSettlementSummary {
                        pending_receipts: row.get::<_, i64>(0)?.max(0) as u64,
                        settled_receipts: row.get::<_, i64>(1)?.max(0) as u64,
                        failed_receipts: row.get::<_, i64>(2)?.max(0) as u64,
                        not_applicable_receipts: row.get::<_, i64>(3)?.max(0) as u64,
                        actionable_receipts: row.get::<_, i64>(4)?.max(0) as u64,
                        reconciled_receipts: row.get::<_, i64>(5)?.max(0) as u64,
                    },
                    BehavioralFeedGovernedActionSummary {
                        governed_receipts: row.get::<_, i64>(6)?.max(0) as u64,
                        approval_receipts: row.get::<_, i64>(7)?.max(0) as u64,
                        approved_receipts: row.get::<_, i64>(8)?.max(0) as u64,
                        commerce_receipts: row.get::<_, i64>(9)?.max(0) as u64,
                        max_amount_receipts: row.get::<_, i64>(10)?.max(0) as u64,
                    },
                ))
            },
        )?;
        let metered_billing = self.query_metered_billing_summary(&operator_query)?;

        let result = self.query_receipts(&query.to_receipt_query())?;
        let mut receipts = Vec::with_capacity(result.receipts.len());
        for stored in result.receipts {
            receipts.push(self.behavioral_feed_receipt_row_from_receipt(stored.receipt)?);
        }

        Ok((
            settlements,
            governed_actions,
            metered_billing,
            BehavioralFeedReceiptSelection {
                matching_receipts: result.total_count,
                receipts,
            },
        ))
    }

    pub fn query_recent_credit_loss_receipts(
        &self,
        query: &BehavioralFeedQuery,
        limit: usize,
    ) -> Result<(u64, Vec<BehavioralFeedReceiptRow>), ReceiptStoreError> {
        let operator_query = query.to_operator_report_query();
        let capability_id = operator_query.capability_id.as_deref();
        let tool_server = operator_query.tool_server.as_deref();
        let tool_name = operator_query.tool_name.as_deref();
        let since = operator_query.since.map(|value| value as i64);
        let until = operator_query.until.map(|value| value as i64);
        let agent_subject = operator_query.agent_subject.as_deref();
        let row_limit = limit.max(1);

        let count_sql = r#"
            SELECT COUNT(*)
            FROM arc_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            LEFT JOIN settlement_reconciliations sr ON r.receipt_id = sr.receipt_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
              AND (
                    COALESCE(json_extract(r.raw_json, '$.metadata.financial.settlement_status'), 'not_applicable') = 'failed'
                    OR (
                        COALESCE(json_extract(r.raw_json, '$.metadata.financial.settlement_status'), 'not_applicable') IN ('pending', 'failed')
                        AND COALESCE(sr.reconciliation_state, 'open') NOT IN ('reconciled', 'ignored')
                    )
              )
        "#;

        let matching_loss_events = self
            .connection
            .query_row(
                count_sql,
                params![
                    capability_id,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    agent_subject
                ],
                |row| row.get::<_, i64>(0),
            )
            .map(|value| value.max(0) as u64)?;

        let rows_sql = r#"
            SELECT r.raw_json
            FROM arc_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            LEFT JOIN settlement_reconciliations sr ON r.receipt_id = sr.receipt_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
              AND (
                    COALESCE(json_extract(r.raw_json, '$.metadata.financial.settlement_status'), 'not_applicable') = 'failed'
                    OR (
                        COALESCE(json_extract(r.raw_json, '$.metadata.financial.settlement_status'), 'not_applicable') IN ('pending', 'failed')
                        AND COALESCE(sr.reconciliation_state, 'open') NOT IN ('reconciled', 'ignored')
                    )
              )
            ORDER BY r.timestamp DESC, r.seq DESC
            LIMIT ?7
        "#;

        let mut stmt = self.connection.prepare(rows_sql)?;
        let rows = stmt.query_map(
            params![
                capability_id,
                tool_server,
                tool_name,
                since,
                until,
                agent_subject,
                row_limit as i64
            ],
            |row| row.get::<_, String>(0),
        )?;

        let mut receipts = Vec::new();
        for row in rows {
            let raw_json = row?;
            let receipt: ArcReceipt = serde_json::from_str(&raw_json)?;
            receipts.push(self.behavioral_feed_receipt_row_from_receipt(receipt)?);
        }

        Ok((matching_loss_events, receipts))
    }

    fn behavioral_feed_receipt_row_from_receipt(
        &self,
        receipt: ArcReceipt,
    ) -> Result<BehavioralFeedReceiptRow, ReceiptStoreError> {
        let attribution = extract_receipt_attribution(&receipt);
        let lineage = if attribution.subject_key.is_none() || attribution.issuer_key.is_none() {
            self.get_combined_lineage(&receipt.capability_id)?
        } else {
            None
        };
        let financial = extract_financial_metadata(&receipt);
        let governed = extract_governed_transaction_metadata(&receipt);
        let metered_reconciliation = governed
            .as_ref()
            .and_then(|metadata| metadata.metered_billing.as_ref())
            .map(|metered| {
                let evidence = self.load_metered_billing_evidence_record(&receipt.id)?;
                let reconciliation_state = self
                    .connection
                    .query_row(
                        r#"
                        SELECT COALESCE(reconciliation_state, 'open')
                        FROM metered_billing_reconciliations
                        WHERE receipt_id = ?1
                        "#,
                        params![&receipt.id],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?
                    .map(|value| parse_metered_billing_reconciliation_state(&value))
                    .transpose()?
                    .unwrap_or(MeteredBillingReconciliationState::Open);
                let analysis = analyze_metered_billing_reconciliation(
                    metered,
                    financial.as_ref(),
                    evidence.as_ref(),
                    reconciliation_state,
                );
                Ok::<BehavioralFeedMeteredBillingRow, ReceiptStoreError>(
                    BehavioralFeedMeteredBillingRow {
                        reconciliation_state,
                        action_required: analysis.action_required,
                        evidence_missing: analysis.evidence_missing,
                        exceeds_quoted_units: analysis.exceeds_quoted_units,
                        exceeds_max_billed_units: analysis.exceeds_max_billed_units,
                        exceeds_quoted_cost: analysis.exceeds_quoted_cost,
                        financial_mismatch: analysis.financial_mismatch,
                        evidence,
                    },
                )
            })
            .transpose()?;
        let settlement_status = financial
            .as_ref()
            .map(|metadata| metadata.settlement_status.clone())
            .unwrap_or(SettlementStatus::NotApplicable);
        let reconciliation_state = self
            .connection
            .query_row(
                r#"
                SELECT COALESCE(reconciliation_state, 'open')
                FROM settlement_reconciliations
                WHERE receipt_id = ?1
                "#,
                params![receipt.id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|value| parse_settlement_reconciliation_state(&value))
            .transpose()?
            .unwrap_or(SettlementReconciliationState::Open);
        let action_required = settlement_reconciliation_action_required(
            settlement_status.clone(),
            reconciliation_state,
        );

        Ok(BehavioralFeedReceiptRow {
            receipt_id: receipt.id,
            timestamp: receipt.timestamp,
            capability_id: receipt.capability_id,
            subject_key: attribution.subject_key.or_else(|| {
                lineage
                    .as_ref()
                    .map(|snapshot| snapshot.subject_key.clone())
            }),
            issuer_key: attribution
                .issuer_key
                .or_else(|| lineage.as_ref().map(|snapshot| snapshot.issuer_key.clone())),
            tool_server: receipt.tool_server,
            tool_name: receipt.tool_name,
            decision: receipt.decision,
            settlement_status,
            reconciliation_state,
            action_required,
            cost_charged: financial.as_ref().map(|metadata| metadata.cost_charged),
            attempted_cost: financial
                .as_ref()
                .and_then(|metadata| metadata.attempted_cost),
            currency: financial.as_ref().map(|metadata| metadata.currency.clone()),
            governed,
            metered_reconciliation,
        })
    }

    fn query_metered_billing_summary(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<BehavioralFeedMeteredBillingSummary, ReceiptStoreError> {
        let capability_id = query.capability_id.as_deref();
        let tool_server = query.tool_server.as_deref();
        let tool_name = query.tool_name.as_deref();
        let since = query.since.map(|value| value as i64);
        let until = query.until.map(|value| value as i64);
        let agent_subject = query.agent_subject.as_deref();

        let summary_sql = r#"
            SELECT
                COUNT(*) AS matching_receipts,
                COALESCE(SUM(CASE WHEN mbr.receipt_id IS NOT NULL THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN mbr.receipt_id IS NULL THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(
                    CASE
                        WHEN mbr.receipt_id IS NOT NULL
                         AND mbr.observed_units > CAST(json_extract(r.raw_json, '$.metadata.governed_transaction.metered_billing.quote.quotedUnits') AS INTEGER)
                        THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN mbr.receipt_id IS NOT NULL
                         AND json_extract(r.raw_json, '$.metadata.governed_transaction.metered_billing.maxBilledUnits') IS NOT NULL
                         AND mbr.observed_units > CAST(json_extract(r.raw_json, '$.metadata.governed_transaction.metered_billing.maxBilledUnits') AS INTEGER)
                        THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN mbr.receipt_id IS NOT NULL
                         AND (
                            mbr.billed_cost_currency != json_extract(r.raw_json, '$.metadata.governed_transaction.metered_billing.quote.quotedCost.currency')
                            OR mbr.billed_cost_units > CAST(json_extract(r.raw_json, '$.metadata.governed_transaction.metered_billing.quote.quotedCost.units') AS INTEGER)
                         )
                        THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN mbr.receipt_id IS NOT NULL
                         AND json_type(r.raw_json, '$.metadata.financial') = 'object'
                         AND (
                            mbr.billed_cost_currency != json_extract(r.raw_json, '$.metadata.financial.currency')
                            OR mbr.billed_cost_units != CAST(json_extract(r.raw_json, '$.metadata.financial.cost_charged') AS INTEGER)
                         )
                        THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN COALESCE(mbr.reconciliation_state, 'open') = 'reconciled' THEN 1
                        ELSE 0
                    END
                ), 0),
                COALESCE(SUM(
                    CASE
                        WHEN COALESCE(mbr.reconciliation_state, 'open') NOT IN ('reconciled', 'ignored')
                         AND (
                            mbr.receipt_id IS NULL
                            OR mbr.observed_units > CAST(json_extract(r.raw_json, '$.metadata.governed_transaction.metered_billing.quote.quotedUnits') AS INTEGER)
                            OR (
                                json_extract(r.raw_json, '$.metadata.governed_transaction.metered_billing.maxBilledUnits') IS NOT NULL
                                AND mbr.observed_units > CAST(json_extract(r.raw_json, '$.metadata.governed_transaction.metered_billing.maxBilledUnits') AS INTEGER)
                            )
                            OR mbr.billed_cost_currency != json_extract(r.raw_json, '$.metadata.governed_transaction.metered_billing.quote.quotedCost.currency')
                            OR mbr.billed_cost_units > CAST(json_extract(r.raw_json, '$.metadata.governed_transaction.metered_billing.quote.quotedCost.units') AS INTEGER)
                            OR (
                                json_type(r.raw_json, '$.metadata.financial') = 'object'
                                AND (
                                    mbr.billed_cost_currency != json_extract(r.raw_json, '$.metadata.financial.currency')
                                    OR mbr.billed_cost_units != CAST(json_extract(r.raw_json, '$.metadata.financial.cost_charged') AS INTEGER)
                                )
                            )
                         )
                        THEN 1
                        ELSE 0
                    END
                ), 0)
            FROM arc_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            LEFT JOIN metered_billing_reconciliations mbr ON r.receipt_id = mbr.receipt_id
            WHERE json_type(r.raw_json, '$.metadata.governed_transaction.metered_billing') = 'object'
              AND (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
        "#;

        let (
            metered_receipts,
            evidence_attached_receipts,
            missing_evidence_receipts,
            over_quoted_units_receipts,
            over_max_billed_units_receipts,
            over_quoted_cost_receipts,
            financial_mismatch_receipts,
            reconciled_receipts,
            actionable_receipts,
        ) = self.connection.query_row(
            summary_sql,
            params![
                capability_id,
                tool_server,
                tool_name,
                since,
                until,
                agent_subject
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?.max(0) as u64,
                    row.get::<_, i64>(1)?.max(0) as u64,
                    row.get::<_, i64>(2)?.max(0) as u64,
                    row.get::<_, i64>(3)?.max(0) as u64,
                    row.get::<_, i64>(4)?.max(0) as u64,
                    row.get::<_, i64>(5)?.max(0) as u64,
                    row.get::<_, i64>(6)?.max(0) as u64,
                    row.get::<_, i64>(7)?.max(0) as u64,
                    row.get::<_, i64>(8)?.max(0) as u64,
                ))
            },
        )?;

        Ok(BehavioralFeedMeteredBillingSummary {
            metered_receipts,
            evidence_attached_receipts,
            missing_evidence_receipts,
            over_quoted_units_receipts,
            over_max_billed_units_receipts,
            over_quoted_cost_receipts,
            financial_mismatch_receipts,
            actionable_receipts,
            reconciled_receipts,
        })
    }

    fn load_metered_billing_evidence_record(
        &self,
        receipt_id: &str,
    ) -> Result<Option<MeteredBillingEvidenceRecord>, ReceiptStoreError> {
        self.connection
            .query_row(
                r#"
                SELECT
                    adapter_kind,
                    evidence_id,
                    observed_units,
                    billed_cost_units,
                    billed_cost_currency,
                    evidence_sha256,
                    recorded_at
                FROM metered_billing_reconciliations
                WHERE receipt_id = ?1
                "#,
                params![receipt_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .optional()?
            .map(
                |(
                    adapter_kind,
                    evidence_id,
                    observed_units,
                    billed_cost_units,
                    billed_cost_currency,
                    evidence_sha256,
                    recorded_at,
                )| {
                    Ok(MeteredBillingEvidenceRecord {
                        usage_evidence: arc_core::receipt::MeteredUsageEvidenceReceiptMetadata {
                            evidence_kind: adapter_kind,
                            evidence_id,
                            observed_units: observed_units.max(0) as u64,
                            evidence_sha256,
                        },
                        billed_cost: arc_core::capability::MonetaryAmount {
                            units: billed_cost_units.max(0) as u64,
                            currency: billed_cost_currency,
                        },
                        recorded_at: recorded_at.max(0) as u64,
                    })
                },
            )
            .transpose()
    }
}

fn unix_timestamp_now_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn settlement_reconciliation_state_text(state: SettlementReconciliationState) -> &'static str {
    match state {
        SettlementReconciliationState::Open => "open",
        SettlementReconciliationState::Reconciled => "reconciled",
        SettlementReconciliationState::Ignored => "ignored",
        SettlementReconciliationState::RetryScheduled => "retry_scheduled",
    }
}

fn parse_settlement_reconciliation_state(
    value: &str,
) -> Result<SettlementReconciliationState, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

fn metered_billing_reconciliation_state_text(
    state: MeteredBillingReconciliationState,
) -> &'static str {
    match state {
        MeteredBillingReconciliationState::Open => "open",
        MeteredBillingReconciliationState::Reconciled => "reconciled",
        MeteredBillingReconciliationState::Ignored => "ignored",
        MeteredBillingReconciliationState::RetryScheduled => "retry_scheduled",
    }
}

fn parse_metered_billing_reconciliation_state(
    value: &str,
) -> Result<MeteredBillingReconciliationState, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

fn underwriting_decision_outcome_label(outcome: UnderwritingDecisionOutcome) -> &'static str {
    match outcome {
        UnderwritingDecisionOutcome::Approve => "approve",
        UnderwritingDecisionOutcome::ReduceCeiling => "reduce_ceiling",
        UnderwritingDecisionOutcome::StepUp => "step_up",
        UnderwritingDecisionOutcome::Deny => "deny",
    }
}

fn underwriting_lifecycle_state_label(state: UnderwritingDecisionLifecycleState) -> &'static str {
    match state {
        UnderwritingDecisionLifecycleState::Active => "active",
        UnderwritingDecisionLifecycleState::Superseded => "superseded",
    }
}

fn underwriting_review_state_label(state: arc_kernel::UnderwritingReviewState) -> &'static str {
    match state {
        arc_kernel::UnderwritingReviewState::Approved => "approved",
        arc_kernel::UnderwritingReviewState::ManualReviewRequired => "manual_review_required",
        arc_kernel::UnderwritingReviewState::Denied => "denied",
    }
}

fn underwriting_risk_class_label(class: arc_kernel::UnderwritingRiskClass) -> &'static str {
    match class {
        arc_kernel::UnderwritingRiskClass::Baseline => "baseline",
        arc_kernel::UnderwritingRiskClass::Guarded => "guarded",
        arc_kernel::UnderwritingRiskClass::Elevated => "elevated",
        arc_kernel::UnderwritingRiskClass::Critical => "critical",
    }
}

fn underwriting_appeal_status_label(status: UnderwritingAppealStatus) -> &'static str {
    match status {
        UnderwritingAppealStatus::Open => "open",
        UnderwritingAppealStatus::Accepted => "accepted",
        UnderwritingAppealStatus::Rejected => "rejected",
    }
}

fn credit_facility_disposition_label(disposition: CreditFacilityDisposition) -> &'static str {
    match disposition {
        CreditFacilityDisposition::Grant => "grant",
        CreditFacilityDisposition::ManualReview => "manual_review",
        CreditFacilityDisposition::Deny => "deny",
    }
}

fn credit_facility_lifecycle_state_label(state: CreditFacilityLifecycleState) -> &'static str {
    match state {
        CreditFacilityLifecycleState::Active => "active",
        CreditFacilityLifecycleState::Superseded => "superseded",
        CreditFacilityLifecycleState::Denied => "denied",
        CreditFacilityLifecycleState::Expired => "expired",
    }
}

fn credit_bond_disposition_label(disposition: CreditBondDisposition) -> &'static str {
    match disposition {
        CreditBondDisposition::Lock => "lock",
        CreditBondDisposition::Hold => "hold",
        CreditBondDisposition::Release => "release",
        CreditBondDisposition::Impair => "impair",
    }
}

fn credit_bond_lifecycle_state_label(state: CreditBondLifecycleState) -> &'static str {
    match state {
        CreditBondLifecycleState::Active => "active",
        CreditBondLifecycleState::Superseded => "superseded",
        CreditBondLifecycleState::Released => "released",
        CreditBondLifecycleState::Impaired => "impaired",
        CreditBondLifecycleState::Expired => "expired",
    }
}

fn liability_provider_lifecycle_state_label(
    state: LiabilityProviderLifecycleState,
) -> &'static str {
    match state {
        LiabilityProviderLifecycleState::Active => "active",
        LiabilityProviderLifecycleState::Suspended => "suspended",
        LiabilityProviderLifecycleState::Superseded => "superseded",
        LiabilityProviderLifecycleState::Retired => "retired",
    }
}

fn credit_loss_lifecycle_event_kind_label(kind: CreditLossLifecycleEventKind) -> &'static str {
    match kind {
        CreditLossLifecycleEventKind::Delinquency => "delinquency",
        CreditLossLifecycleEventKind::Recovery => "recovery",
        CreditLossLifecycleEventKind::ReserveRelease => "reserve_release",
        CreditLossLifecycleEventKind::WriteOff => "write_off",
    }
}

fn parse_underwriting_lifecycle_state(
    value: &str,
) -> Result<UnderwritingDecisionLifecycleState, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

fn parse_credit_facility_lifecycle_state(
    value: &str,
) -> Result<CreditFacilityLifecycleState, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

fn parse_credit_bond_lifecycle_state(
    value: &str,
) -> Result<CreditBondLifecycleState, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

fn parse_liability_provider_lifecycle_state(
    value: &str,
) -> Result<LiabilityProviderLifecycleState, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

fn liability_quote_disposition_label(disposition: &LiabilityQuoteDisposition) -> &'static str {
    match disposition {
        LiabilityQuoteDisposition::Quoted => "quoted",
        LiabilityQuoteDisposition::Declined => "declined",
    }
}

fn query_underwriting_appeal(
    tx: &rusqlite::Transaction<'_>,
    appeal_id: &str,
) -> Result<Option<UnderwritingAppealRecord>, ReceiptStoreError> {
    let row = tx
        .query_row(
            "SELECT decision_id, requested_by, reason, status, note, created_at, updated_at,
                resolved_by, replacement_decision_id
         FROM underwriting_appeals
         WHERE appeal_id = ?1",
            params![appeal_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                ))
            },
        )
        .optional()
        .map_err(ReceiptStoreError::from)?;

    row.map(
        |(
            decision_id,
            requested_by,
            reason,
            status,
            note,
            created_at,
            updated_at,
            resolved_by,
            replacement_decision_id,
        )| {
            Ok(UnderwritingAppealRecord {
                schema: arc_kernel::UNDERWRITING_APPEAL_SCHEMA.to_string(),
                appeal_id: appeal_id.to_string(),
                decision_id,
                requested_by,
                reason,
                status: parse_underwriting_appeal_status(&status)?,
                note,
                created_at: created_at.max(0) as u64,
                updated_at: updated_at.max(0) as u64,
                resolved_by,
                replacement_decision_id,
            })
        },
    )
    .transpose()
}

fn parse_underwriting_appeal_status(
    value: &str,
) -> Result<UnderwritingAppealStatus, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

fn load_underwriting_appeal_rows(
    connection: &Connection,
) -> Result<Vec<UnderwritingAppealRecord>, ReceiptStoreError> {
    let mut statement = connection.prepare(
        "SELECT appeal_id, decision_id, requested_by, reason, status, note, created_at,
                updated_at, resolved_by, replacement_decision_id
         FROM underwriting_appeals
         ORDER BY updated_at DESC, appeal_id DESC",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, i64>(7)?,
            row.get::<_, Option<String>>(8)?,
            row.get::<_, Option<String>>(9)?,
        ))
    })?;
    rows.map(|row| {
        let (
            appeal_id,
            decision_id,
            requested_by,
            reason,
            status,
            note,
            created_at,
            updated_at,
            resolved_by,
            replacement_decision_id,
        ) = row?;
        Ok(UnderwritingAppealRecord {
            schema: arc_kernel::UNDERWRITING_APPEAL_SCHEMA.to_string(),
            appeal_id,
            decision_id,
            requested_by,
            reason,
            status: parse_underwriting_appeal_status(&status)?,
            note,
            created_at: created_at.max(0) as u64,
            updated_at: updated_at.max(0) as u64,
            resolved_by,
            replacement_decision_id,
        })
    })
    .collect()
}

fn underwriting_decision_matches_query(
    decision: &SignedUnderwritingDecision,
    lifecycle_state: UnderwritingDecisionLifecycleState,
    latest_appeal_status: Option<UnderwritingAppealStatus>,
    query: &UnderwritingDecisionQuery,
) -> bool {
    let filters = &decision.body.evaluation.input.filters;
    let decision_id_matches = query
        .decision_id
        .as_deref()
        .is_none_or(|decision_id| decision.body.decision_id == decision_id);
    let capability_matches = query
        .capability_id
        .as_deref()
        .is_none_or(|capability_id| filters.capability_id.as_deref() == Some(capability_id));
    let subject_matches = query
        .agent_subject
        .as_deref()
        .is_none_or(|subject| filters.agent_subject.as_deref() == Some(subject));
    let tool_server_matches = query
        .tool_server
        .as_deref()
        .is_none_or(|tool_server| filters.tool_server.as_deref() == Some(tool_server));
    let tool_name_matches = query
        .tool_name
        .as_deref()
        .is_none_or(|tool_name| filters.tool_name.as_deref() == Some(tool_name));
    let outcome_matches = query
        .outcome
        .is_none_or(|outcome| decision.body.evaluation.outcome == outcome);
    let lifecycle_matches = query
        .lifecycle_state
        .is_none_or(|state| lifecycle_state == state);
    let appeal_matches = query
        .appeal_status
        .is_none_or(|status| latest_appeal_status == Some(status));

    decision_id_matches
        && capability_matches
        && subject_matches
        && tool_server_matches
        && tool_name_matches
        && outcome_matches
        && lifecycle_matches
        && appeal_matches
}

fn effective_credit_facility_lifecycle_state(
    facility: &SignedCreditFacility,
    persisted: CreditFacilityLifecycleState,
    now: u64,
) -> CreditFacilityLifecycleState {
    if persisted == CreditFacilityLifecycleState::Active && facility.body.expires_at <= now {
        CreditFacilityLifecycleState::Expired
    } else {
        persisted
    }
}

fn effective_credit_bond_lifecycle_state(
    bond: &SignedCreditBond,
    persisted: CreditBondLifecycleState,
    now: u64,
) -> CreditBondLifecycleState {
    if persisted == CreditBondLifecycleState::Active && bond.body.expires_at <= now {
        CreditBondLifecycleState::Expired
    } else {
        persisted
    }
}

fn credit_facility_matches_query(
    facility: &SignedCreditFacility,
    lifecycle_state: CreditFacilityLifecycleState,
    query: &CreditFacilityListQuery,
) -> bool {
    let filters = &facility.body.report.filters;
    let facility_id_matches = query
        .facility_id
        .as_deref()
        .is_none_or(|facility_id| facility.body.facility_id == facility_id);
    let capability_matches = query
        .capability_id
        .as_deref()
        .is_none_or(|capability_id| filters.capability_id.as_deref() == Some(capability_id));
    let subject_matches = query
        .agent_subject
        .as_deref()
        .is_none_or(|subject| filters.agent_subject.as_deref() == Some(subject));
    let tool_server_matches = query
        .tool_server
        .as_deref()
        .is_none_or(|tool_server| filters.tool_server.as_deref() == Some(tool_server));
    let tool_name_matches = query
        .tool_name
        .as_deref()
        .is_none_or(|tool_name| filters.tool_name.as_deref() == Some(tool_name));
    let disposition_matches = query
        .disposition
        .is_none_or(|disposition| facility.body.report.disposition == disposition);
    let lifecycle_matches = query
        .lifecycle_state
        .is_none_or(|state| lifecycle_state == state);

    facility_id_matches
        && capability_matches
        && subject_matches
        && tool_server_matches
        && tool_name_matches
        && disposition_matches
        && lifecycle_matches
}

fn credit_bond_matches_query(
    bond: &SignedCreditBond,
    lifecycle_state: CreditBondLifecycleState,
    query: &CreditBondListQuery,
) -> bool {
    let filters = &bond.body.report.filters;
    let bond_id_matches = query
        .bond_id
        .as_deref()
        .is_none_or(|bond_id| bond.body.bond_id == bond_id);
    let facility_id_matches = query.facility_id.as_deref().is_none_or(|facility_id| {
        bond.body.report.latest_facility_id.as_deref() == Some(facility_id)
    });
    let capability_matches = query
        .capability_id
        .as_deref()
        .is_none_or(|capability_id| filters.capability_id.as_deref() == Some(capability_id));
    let subject_matches = query
        .agent_subject
        .as_deref()
        .is_none_or(|subject| filters.agent_subject.as_deref() == Some(subject));
    let tool_server_matches = query
        .tool_server
        .as_deref()
        .is_none_or(|tool_server| filters.tool_server.as_deref() == Some(tool_server));
    let tool_name_matches = query
        .tool_name
        .as_deref()
        .is_none_or(|tool_name| filters.tool_name.as_deref() == Some(tool_name));
    let disposition_matches = query
        .disposition
        .is_none_or(|disposition| bond.body.report.disposition == disposition);
    let lifecycle_matches = query
        .lifecycle_state
        .is_none_or(|state| lifecycle_state == state);

    bond_id_matches
        && facility_id_matches
        && capability_matches
        && subject_matches
        && tool_server_matches
        && tool_name_matches
        && disposition_matches
        && lifecycle_matches
}

fn liability_provider_matches_query(
    provider: &SignedLiabilityProvider,
    lifecycle_state: LiabilityProviderLifecycleState,
    query: &LiabilityProviderListQuery,
) -> bool {
    let report = &provider.body.report;
    let provider_id_matches = query
        .provider_id
        .as_deref()
        .is_none_or(|provider_id| report.provider_id == provider_id);
    let lifecycle_matches = query
        .lifecycle_state
        .is_none_or(|state| lifecycle_state == state);
    let jurisdiction_matches = query.jurisdiction.as_deref().is_none_or(|jurisdiction| {
        report
            .policies
            .iter()
            .any(|policy| policy.jurisdiction.eq_ignore_ascii_case(jurisdiction))
    });
    let coverage_matches = query.coverage_class.is_none_or(|coverage_class| {
        report
            .policies
            .iter()
            .any(|policy| policy.coverage_classes.contains(&coverage_class))
    });
    let currency_matches = query.currency.as_deref().is_none_or(|currency| {
        report.policies.iter().any(|policy| {
            policy
                .supported_currencies
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(currency))
        })
    });

    provider_id_matches
        && lifecycle_matches
        && jurisdiction_matches
        && coverage_matches
        && currency_matches
}

fn liability_provider_policy_matches_resolution(
    policy: &arc_kernel::LiabilityJurisdictionPolicy,
    query: &LiabilityProviderResolutionQuery,
) -> bool {
    policy
        .jurisdiction
        .eq_ignore_ascii_case(&query.jurisdiction)
        && policy.coverage_classes.contains(&query.coverage_class)
        && policy
            .supported_currencies
            .iter()
            .any(|currency| currency.eq_ignore_ascii_case(&query.currency))
}

fn liability_market_workflow_matches_query(
    quote_request: &SignedLiabilityQuoteRequest,
    query: &LiabilityMarketWorkflowQuery,
) -> bool {
    let request = &quote_request.body;
    let quote_request_id_matches = query
        .quote_request_id
        .as_deref()
        .is_none_or(|quote_request_id| request.quote_request_id == quote_request_id);
    let provider_id_matches = query
        .provider_id
        .as_deref()
        .is_none_or(|provider_id| request.provider_policy.provider_id == provider_id);
    let subject_matches = query
        .agent_subject
        .as_deref()
        .is_none_or(|subject| request.risk_package.body.subject_key == subject);
    let jurisdiction_matches = query.jurisdiction.as_deref().is_none_or(|jurisdiction| {
        request
            .provider_policy
            .jurisdiction
            .eq_ignore_ascii_case(jurisdiction)
    });
    let coverage_matches = query
        .coverage_class
        .is_none_or(|coverage_class| request.provider_policy.coverage_class == coverage_class);
    let currency_matches = query.currency.as_deref().is_none_or(|currency| {
        request
            .requested_coverage_amount
            .currency
            .eq_ignore_ascii_case(currency)
    });

    quote_request_id_matches
        && provider_id_matches
        && subject_matches
        && jurisdiction_matches
        && coverage_matches
        && currency_matches
}

fn liability_claim_workflow_matches_query(
    claim: &SignedLiabilityClaimPackage,
    query: &LiabilityClaimWorkflowQuery,
) -> bool {
    let claim_body = &claim.body;
    let provider_policy = &claim_body
        .bound_coverage
        .body
        .placement
        .body
        .quote_response
        .body
        .quote_request
        .body
        .provider_policy;
    let claim_id_matches = query
        .claim_id
        .as_deref()
        .is_none_or(|claim_id| claim_body.claim_id == claim_id);
    let provider_id_matches = query
        .provider_id
        .as_deref()
        .is_none_or(|provider_id| provider_policy.provider_id == provider_id);
    let subject_matches = query.agent_subject.as_deref().is_none_or(|subject| {
        claim_body
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
            .subject_key
            == subject
    });
    let jurisdiction_matches = query.jurisdiction.as_deref().is_none_or(|jurisdiction| {
        provider_policy
            .jurisdiction
            .eq_ignore_ascii_case(jurisdiction)
    });
    let policy_number_matches = query
        .policy_number
        .as_deref()
        .is_none_or(|policy_number| claim_body.bound_coverage.body.policy_number == policy_number);

    claim_id_matches
        && provider_id_matches
        && subject_matches
        && jurisdiction_matches
        && policy_number_matches
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs()
}

fn parse_settlement_status(value: &str) -> Result<SettlementStatus, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

fn settlement_reconciliation_action_required(
    settlement_status: SettlementStatus,
    reconciliation_state: SettlementReconciliationState,
) -> bool {
    matches!(
        settlement_status,
        SettlementStatus::Pending | SettlementStatus::Failed
    ) && !matches!(
        reconciliation_state,
        SettlementReconciliationState::Reconciled | SettlementReconciliationState::Ignored
    )
}

fn metered_billing_evidence_record_from_columns(
    adapter_kind: Option<String>,
    evidence_id: Option<String>,
    observed_units: Option<i64>,
    billed_cost_units: Option<i64>,
    billed_cost_currency: Option<String>,
    evidence_sha256: Option<String>,
    recorded_at: Option<i64>,
) -> Option<MeteredBillingEvidenceRecord> {
    let (
        Some(adapter_kind),
        Some(evidence_id),
        Some(observed_units),
        Some(billed_cost_units),
        Some(billed_cost_currency),
        Some(recorded_at),
    ) = (
        adapter_kind,
        evidence_id,
        observed_units,
        billed_cost_units,
        billed_cost_currency,
        recorded_at,
    )
    else {
        return None;
    };

    Some(MeteredBillingEvidenceRecord {
        usage_evidence: arc_core::receipt::MeteredUsageEvidenceReceiptMetadata {
            evidence_kind: adapter_kind,
            evidence_id,
            observed_units: observed_units.max(0) as u64,
            evidence_sha256,
        },
        billed_cost: arc_core::capability::MonetaryAmount {
            units: billed_cost_units.max(0) as u64,
            currency: billed_cost_currency,
        },
        recorded_at: recorded_at.max(0) as u64,
    })
}

struct MeteredBillingReconciliationAnalysis {
    evidence_missing: bool,
    exceeds_quoted_units: bool,
    exceeds_max_billed_units: bool,
    exceeds_quoted_cost: bool,
    financial_mismatch: bool,
    action_required: bool,
}

fn analyze_metered_billing_reconciliation(
    metered: &arc_core::receipt::MeteredBillingReceiptMetadata,
    financial: Option<&FinancialReceiptMetadata>,
    evidence: Option<&MeteredBillingEvidenceRecord>,
    reconciliation_state: MeteredBillingReconciliationState,
) -> MeteredBillingReconciliationAnalysis {
    let evidence_missing = evidence.is_none();
    let exceeds_quoted_units = evidence
        .is_some_and(|record| record.usage_evidence.observed_units > metered.quote.quoted_units);
    let exceeds_max_billed_units = evidence.is_some_and(|record| {
        metered
            .max_billed_units
            .is_some_and(|max_units| record.usage_evidence.observed_units > max_units)
    });
    let exceeds_quoted_cost = evidence.is_some_and(|record| {
        record.billed_cost.currency != metered.quote.quoted_cost.currency
            || record.billed_cost.units > metered.quote.quoted_cost.units
    });
    let financial_mismatch = evidence.is_some_and(|record| {
        financial.is_some_and(|financial| {
            record.billed_cost.currency != financial.currency
                || record.billed_cost.units != financial.cost_charged
        })
    });
    let action_required = (evidence_missing
        || exceeds_quoted_units
        || exceeds_max_billed_units
        || exceeds_quoted_cost
        || financial_mismatch)
        && !matches!(
            reconciliation_state,
            MeteredBillingReconciliationState::Reconciled
                | MeteredBillingReconciliationState::Ignored
        );

    MeteredBillingReconciliationAnalysis {
        evidence_missing,
        exceeds_quoted_units,
        exceeds_max_billed_units,
        exceeds_quoted_cost,
        financial_mismatch,
        action_required,
    }
}

#[derive(Default)]
struct RootAggregate {
    receipt_count: u64,
    total_cost_charged: u64,
    total_attempted_cost: u64,
    max_delegation_depth: u64,
    leaf_subjects: BTreeSet<String>,
}

#[derive(Default)]
struct LeafAggregate {
    receipt_count: u64,
    total_cost_charged: u64,
    total_attempted_cost: u64,
    max_delegation_depth: u64,
}

#[derive(Default)]
struct ReceiptAttributionColumns {
    subject_key: Option<String>,
    issuer_key: Option<String>,
    grant_index: Option<u32>,
}

fn extract_receipt_attribution(receipt: &ArcReceipt) -> ReceiptAttributionColumns {
    let Some(metadata) = receipt.metadata.as_ref() else {
        return ReceiptAttributionColumns::default();
    };

    let attribution = metadata
        .get("attribution")
        .cloned()
        .and_then(|value| serde_json::from_value::<ReceiptAttributionMetadata>(value).ok());
    let grant_index = attribution
        .as_ref()
        .and_then(|value| value.grant_index)
        .or_else(|| {
            metadata
                .get("financial")
                .and_then(|value| value.get("grant_index"))
                .and_then(serde_json::Value::as_u64)
                .map(|value| value as u32)
        });

    ReceiptAttributionColumns {
        subject_key: attribution.as_ref().map(|value| value.subject_key.clone()),
        issuer_key: attribution.as_ref().map(|value| value.issuer_key.clone()),
        grant_index,
    }
}

fn extract_financial_metadata(receipt: &ArcReceipt) -> Option<FinancialReceiptMetadata> {
    receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("financial"))
        .cloned()
        .and_then(|value| serde_json::from_value::<FinancialReceiptMetadata>(value).ok())
}

fn extract_governed_transaction_metadata(
    receipt: &ArcReceipt,
) -> Option<GovernedTransactionReceiptMetadata> {
    receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .cloned()
        .and_then(|value| serde_json::from_value::<GovernedTransactionReceiptMetadata>(value).ok())
}

fn authorization_details_from_governed_metadata(
    governed: &GovernedTransactionReceiptMetadata,
) -> Vec<GovernedAuthorizationDetail> {
    let mut details = vec![GovernedAuthorizationDetail {
        detail_type: ARC_OAUTH_AUTHORIZATION_TOOL_DETAIL_TYPE.to_string(),
        locations: vec![governed.server_id.clone()],
        actions: vec![governed.tool_name.clone()],
        purpose: Some(governed.purpose.clone()),
        max_amount: governed.max_amount.clone(),
        commerce: None,
        metered_billing: None,
    }];

    if let Some(commerce) = governed.commerce.as_ref() {
        details.push(GovernedAuthorizationDetail {
            detail_type: ARC_OAUTH_AUTHORIZATION_COMMERCE_DETAIL_TYPE.to_string(),
            locations: Vec::new(),
            actions: Vec::new(),
            purpose: None,
            max_amount: governed.max_amount.clone(),
            commerce: Some(GovernedAuthorizationCommerceDetail {
                seller: commerce.seller.clone(),
                shared_payment_token_id: commerce.shared_payment_token_id.clone(),
            }),
            metered_billing: None,
        });
    }

    if let Some(metered) = governed.metered_billing.as_ref() {
        details.push(GovernedAuthorizationDetail {
            detail_type: ARC_OAUTH_AUTHORIZATION_METERED_BILLING_DETAIL_TYPE.to_string(),
            locations: Vec::new(),
            actions: Vec::new(),
            purpose: None,
            max_amount: None,
            commerce: None,
            metered_billing: Some(GovernedAuthorizationMeteredBillingDetail {
                settlement_mode: metered.settlement_mode,
                provider: metered.quote.provider.clone(),
                quote_id: metered.quote.quote_id.clone(),
                billing_unit: metered.quote.billing_unit.clone(),
                quoted_units: metered.quote.quoted_units,
                quoted_cost: metered.quote.quoted_cost.clone(),
                max_billed_units: metered.max_billed_units,
            }),
        });
    }

    details
}

fn authorization_transaction_context_from_governed_metadata(
    governed: &GovernedTransactionReceiptMetadata,
) -> GovernedAuthorizationTransactionContext {
    GovernedAuthorizationTransactionContext {
        intent_id: governed.intent_id.clone(),
        intent_hash: governed.intent_hash.clone(),
        approval_token_id: governed
            .approval
            .as_ref()
            .map(|value| value.token_id.clone()),
        approval_approved: governed.approval.as_ref().map(|value| value.approved),
        approver_key: governed
            .approval
            .as_ref()
            .map(|value| value.approver_key.clone()),
        runtime_assurance_tier: governed.runtime_assurance.as_ref().map(|value| value.tier),
        runtime_assurance_verifier: governed
            .runtime_assurance
            .as_ref()
            .map(|value| value.verifier.clone()),
        runtime_assurance_evidence_sha256: governed
            .runtime_assurance
            .as_ref()
            .map(|value| value.evidence_sha256.clone()),
        call_chain: governed.call_chain.clone(),
        identity_assertion: None,
    }
}

fn resolve_sender_constraint_subject_key(
    receipt_id: &str,
    receipt_subject_key: Option<&str>,
    lineage_subject_key: Option<&str>,
) -> Result<(String, String), ReceiptStoreError> {
    match (receipt_subject_key, lineage_subject_key) {
        (Some(receipt_key), Some(lineage_key)) => {
            ensure_non_empty_profile_value(receipt_id, "senderConstraint.subjectKey", receipt_key)?;
            ensure_non_empty_profile_value(receipt_id, "capabilitySnapshot.subjectKey", lineage_key)?;
            if receipt_key != lineage_key {
                return Err(invalid_arc_oauth_authorization_profile(
                    receipt_id,
                    format!(
                        "senderConstraint.subjectKey `{receipt_key}` does not match capability snapshot subject `{lineage_key}`"
                    ),
                ));
            }
            Ok((receipt_key.to_string(), "receipt_attribution".to_string()))
        }
        (Some(receipt_key), None) => {
            ensure_non_empty_profile_value(receipt_id, "senderConstraint.subjectKey", receipt_key)?;
            Ok((receipt_key.to_string(), "receipt_attribution".to_string()))
        }
        (None, Some(lineage_key)) => {
            ensure_non_empty_profile_value(receipt_id, "senderConstraint.subjectKey", lineage_key)?;
            Ok((lineage_key.to_string(), "capability_snapshot".to_string()))
        }
        (None, None) => Err(invalid_arc_oauth_authorization_profile(
            receipt_id,
            "sender-constrained profile requires a bound subjectKey from receipt attribution or capability snapshot",
        )),
    }
}

fn resolve_sender_constraint_issuer_key(
    receipt_id: &str,
    receipt_issuer_key: Option<&str>,
    lineage_issuer_key: Option<&str>,
) -> Result<(String, String), ReceiptStoreError> {
    match (receipt_issuer_key, lineage_issuer_key) {
        (Some(receipt_key), Some(lineage_key)) => {
            ensure_non_empty_profile_value(receipt_id, "senderConstraint.issuerKey", receipt_key)?;
            ensure_non_empty_profile_value(receipt_id, "capabilitySnapshot.issuerKey", lineage_key)?;
            if receipt_key != lineage_key {
                return Err(invalid_arc_oauth_authorization_profile(
                    receipt_id,
                    format!(
                        "senderConstraint.issuerKey `{receipt_key}` does not match capability snapshot issuer `{lineage_key}`"
                    ),
                ));
            }
            Ok((receipt_key.to_string(), "receipt_attribution".to_string()))
        }
        (Some(receipt_key), None) => {
            ensure_non_empty_profile_value(receipt_id, "senderConstraint.issuerKey", receipt_key)?;
            Ok((receipt_key.to_string(), "receipt_attribution".to_string()))
        }
        (None, Some(lineage_key)) => {
            ensure_non_empty_profile_value(receipt_id, "senderConstraint.issuerKey", lineage_key)?;
            Ok((lineage_key.to_string(), "capability_snapshot".to_string()))
        }
        (None, None) => Err(invalid_arc_oauth_authorization_profile(
            receipt_id,
            "sender-constrained profile requires a bound issuerKey from receipt attribution or capability snapshot",
        )),
    }
}

fn resolve_sender_constraint_grant(
    receipt_id: &str,
    tool_server: &str,
    tool_name: &str,
    grant_index: Option<u32>,
    grants_json: Option<&str>,
) -> Result<(u32, bool), ReceiptStoreError> {
    let grants_json = grants_json.ok_or_else(|| {
        invalid_arc_oauth_authorization_profile(
            receipt_id,
            "sender-constrained profile requires capability snapshot grants_json",
        )
    })?;
    let scope: ArcScope = serde_json::from_str(grants_json).map_err(|error| {
        invalid_arc_oauth_authorization_profile(
            receipt_id,
            format!("invalid capability snapshot grants_json: {error}"),
        )
    })?;

    if let Some(index) = grant_index {
        let grant = scope.grants.get(index as usize).ok_or_else(|| {
            invalid_arc_oauth_authorization_profile(
                receipt_id,
                format!("matched grant_index `{index}` is outside the capability scope"),
            )
        })?;
        if grant.server_id != tool_server || grant.tool_name != tool_name {
            return Err(invalid_arc_oauth_authorization_profile(
                receipt_id,
                format!(
                    "grant_index `{index}` resolves to {}/{} instead of {tool_server}/{tool_name}",
                    grant.server_id, grant.tool_name
                ),
            ));
        }
        return Ok((index, grant.dpop_required == Some(true)));
    }

    let mut matches = scope
        .grants
        .iter()
        .enumerate()
        .filter(|(_, grant)| grant.server_id == tool_server && grant.tool_name == tool_name);
    let Some((index, grant)) = matches.next() else {
        return Err(invalid_arc_oauth_authorization_profile(
            receipt_id,
            format!("capability snapshot does not contain a grant for {tool_server}/{tool_name}"),
        ));
    };
    if matches.next().is_some() {
        return Err(invalid_arc_oauth_authorization_profile(
            receipt_id,
            format!(
                "capability snapshot contains multiple grants for {tool_server}/{tool_name}; grant_index is required"
            ),
        ));
    }
    Ok((index as u32, grant.dpop_required == Some(true)))
}

fn derive_authorization_sender_constraint(
    receipt_id: &str,
    tool_server: &str,
    tool_name: &str,
    receipt_subject_key: Option<&str>,
    receipt_issuer_key: Option<&str>,
    lineage_subject_key: Option<&str>,
    lineage_issuer_key: Option<&str>,
    grant_index: Option<u32>,
    grants_json: Option<&str>,
    transaction_context: &GovernedAuthorizationTransactionContext,
) -> Result<AuthorizationContextSenderConstraint, ReceiptStoreError> {
    let (subject_key, subject_key_source) = resolve_sender_constraint_subject_key(
        receipt_id,
        receipt_subject_key,
        lineage_subject_key,
    )?;
    let (issuer_key, issuer_key_source) =
        resolve_sender_constraint_issuer_key(receipt_id, receipt_issuer_key, lineage_issuer_key)?;
    let (matched_grant_index, proof_required) = resolve_sender_constraint_grant(
        receipt_id,
        tool_server,
        tool_name,
        grant_index,
        grants_json,
    )?;

    Ok(AuthorizationContextSenderConstraint {
        subject_key,
        subject_key_source,
        issuer_key,
        issuer_key_source,
        matched_grant_index,
        proof_required,
        proof_type: proof_required.then(|| ARC_OAUTH_SENDER_PROOF_ARC_DPOP.to_string()),
        proof_schema: proof_required.then(|| DPOP_SCHEMA.to_string()),
        runtime_assurance_bound: transaction_context.runtime_assurance_tier.is_some(),
        delegated_call_chain_bound: transaction_context.call_chain.is_some(),
    })
}

fn invalid_arc_oauth_authorization_profile(
    receipt_id: &str,
    detail: impl AsRef<str>,
) -> ReceiptStoreError {
    ReceiptStoreError::Canonical(format!(
        "receipt {receipt_id} violates ARC OAuth authorization profile: {}",
        detail.as_ref()
    ))
}

fn ensure_non_empty_profile_value(
    receipt_id: &str,
    field: &str,
    value: &str,
) -> Result<(), ReceiptStoreError> {
    if value.trim().is_empty() {
        return Err(invalid_arc_oauth_authorization_profile(
            receipt_id,
            format!("{field} must not be empty"),
        ));
    }
    Ok(())
}

fn validate_arc_oauth_authorization_detail(
    receipt_id: &str,
    detail: &GovernedAuthorizationDetail,
) -> Result<bool, ReceiptStoreError> {
    match detail.detail_type.as_str() {
        ARC_OAUTH_AUTHORIZATION_TOOL_DETAIL_TYPE => {
            if detail.locations.is_empty() {
                return Err(invalid_arc_oauth_authorization_profile(
                    receipt_id,
                    "arc_governed_tool must include at least one location",
                ));
            }
            if detail.actions.is_empty() {
                return Err(invalid_arc_oauth_authorization_profile(
                    receipt_id,
                    "arc_governed_tool must include at least one action",
                ));
            }
            for location in &detail.locations {
                ensure_non_empty_profile_value(
                    receipt_id,
                    "authorizationDetails.locations[]",
                    location,
                )?;
            }
            for action in &detail.actions {
                ensure_non_empty_profile_value(
                    receipt_id,
                    "authorizationDetails.actions[]",
                    action,
                )?;
            }
            if detail.commerce.is_some() || detail.metered_billing.is_some() {
                return Err(invalid_arc_oauth_authorization_profile(
                    receipt_id,
                    "arc_governed_tool must not carry commerce or meteredBilling sidecars",
                ));
            }
            Ok(true)
        }
        ARC_OAUTH_AUTHORIZATION_COMMERCE_DETAIL_TYPE => {
            let Some(commerce) = detail.commerce.as_ref() else {
                return Err(invalid_arc_oauth_authorization_profile(
                    receipt_id,
                    "arc_governed_commerce must include commerce detail",
                ));
            };
            ensure_non_empty_profile_value(
                receipt_id,
                "authorizationDetails.commerce.seller",
                &commerce.seller,
            )?;
            ensure_non_empty_profile_value(
                receipt_id,
                "authorizationDetails.commerce.sharedPaymentTokenId",
                &commerce.shared_payment_token_id,
            )?;
            if detail.metered_billing.is_some() {
                return Err(invalid_arc_oauth_authorization_profile(
                    receipt_id,
                    "arc_governed_commerce must not carry meteredBilling detail",
                ));
            }
            Ok(false)
        }
        ARC_OAUTH_AUTHORIZATION_METERED_BILLING_DETAIL_TYPE => {
            let Some(metered) = detail.metered_billing.as_ref() else {
                return Err(invalid_arc_oauth_authorization_profile(
                    receipt_id,
                    "arc_governed_metered_billing must include meteredBilling detail",
                ));
            };
            ensure_non_empty_profile_value(
                receipt_id,
                "authorizationDetails.meteredBilling.provider",
                &metered.provider,
            )?;
            ensure_non_empty_profile_value(
                receipt_id,
                "authorizationDetails.meteredBilling.quoteId",
                &metered.quote_id,
            )?;
            ensure_non_empty_profile_value(
                receipt_id,
                "authorizationDetails.meteredBilling.billingUnit",
                &metered.billing_unit,
            )?;
            if detail.commerce.is_some() {
                return Err(invalid_arc_oauth_authorization_profile(
                    receipt_id,
                    "arc_governed_metered_billing must not carry commerce detail",
                ));
            }
            Ok(false)
        }
        unsupported => Err(invalid_arc_oauth_authorization_profile(
            receipt_id,
            format!("unsupported authorizationDetails.type `{unsupported}`"),
        )),
    }
}

fn validate_arc_oauth_authorization_row(
    row: &AuthorizationContextRow,
) -> Result<(), ReceiptStoreError> {
    ensure_non_empty_profile_value(
        &row.receipt_id,
        "transactionContext.intentId",
        &row.transaction_context.intent_id,
    )?;
    ensure_non_empty_profile_value(
        &row.receipt_id,
        "transactionContext.intentHash",
        &row.transaction_context.intent_hash,
    )?;

    let mut saw_tool_detail = false;
    for detail in &row.authorization_details {
        if validate_arc_oauth_authorization_detail(&row.receipt_id, detail)? {
            saw_tool_detail = true;
        }
    }
    if !saw_tool_detail {
        return Err(invalid_arc_oauth_authorization_profile(
            &row.receipt_id,
            "report must include one arc_governed_tool authorization detail",
        ));
    }

    if let Some(token_id) = row.transaction_context.approval_token_id.as_deref() {
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.approvalTokenId",
            token_id,
        )?;
        let approver_key = row
            .transaction_context
            .approver_key
            .as_deref()
            .ok_or_else(|| {
                invalid_arc_oauth_authorization_profile(
                    &row.receipt_id,
                    "approvalTokenId requires approverKey",
                )
            })?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.approverKey",
            approver_key,
        )?;
        if row.transaction_context.approval_approved.is_none() {
            return Err(invalid_arc_oauth_authorization_profile(
                &row.receipt_id,
                "approvalTokenId requires approvalApproved",
            ));
        }
    }

    if let Some(call_chain) = row.transaction_context.call_chain.as_ref() {
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.callChain.chainId",
            &call_chain.chain_id,
        )?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.callChain.parentRequestId",
            &call_chain.parent_request_id,
        )?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.callChain.originSubject",
            &call_chain.origin_subject,
        )?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.callChain.delegatorSubject",
            &call_chain.delegator_subject,
        )?;
        if let Some(parent_receipt_id) = call_chain.parent_receipt_id.as_deref() {
            ensure_non_empty_profile_value(
                &row.receipt_id,
                "transactionContext.callChain.parentReceiptId",
                parent_receipt_id,
            )?;
        }
    }

    if row.transaction_context.runtime_assurance_tier.is_some() {
        let runtime_assurance_verifier = row
            .transaction_context
            .runtime_assurance_verifier
            .as_deref()
            .ok_or_else(|| {
                invalid_arc_oauth_authorization_profile(
                    &row.receipt_id,
                    "runtimeAssuranceTier requires runtimeAssuranceVerifier",
                )
            })?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.runtimeAssuranceVerifier",
            runtime_assurance_verifier,
        )?;
        let runtime_assurance_evidence_sha256 = row
            .transaction_context
            .runtime_assurance_evidence_sha256
            .as_deref()
            .ok_or_else(|| {
                invalid_arc_oauth_authorization_profile(
                    &row.receipt_id,
                    "runtimeAssuranceTier requires runtimeAssuranceEvidenceSha256",
                )
            })?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.runtimeAssuranceEvidenceSha256",
            runtime_assurance_evidence_sha256,
        )?;
    }

    ensure_non_empty_profile_value(
        &row.receipt_id,
        "senderConstraint.subjectKey",
        &row.sender_constraint.subject_key,
    )?;
    if row.subject_key.as_deref() != Some(row.sender_constraint.subject_key.as_str()) {
        return Err(invalid_arc_oauth_authorization_profile(
            &row.receipt_id,
            "row subjectKey must match senderConstraint.subjectKey",
        ));
    }
    ensure_non_empty_profile_value(
        &row.receipt_id,
        "senderConstraint.subjectKeySource",
        &row.sender_constraint.subject_key_source,
    )?;
    ensure_non_empty_profile_value(
        &row.receipt_id,
        "senderConstraint.issuerKey",
        &row.sender_constraint.issuer_key,
    )?;
    ensure_non_empty_profile_value(
        &row.receipt_id,
        "senderConstraint.issuerKeySource",
        &row.sender_constraint.issuer_key_source,
    )?;
    if row.sender_constraint.proof_required {
        let proof_type = row.sender_constraint.proof_type.as_deref().ok_or_else(|| {
            invalid_arc_oauth_authorization_profile(
                &row.receipt_id,
                "proofRequired requires senderConstraint.proofType",
            )
        })?;
        ensure_non_empty_profile_value(&row.receipt_id, "senderConstraint.proofType", proof_type)?;
        let proof_schema = row
            .sender_constraint
            .proof_schema
            .as_deref()
            .ok_or_else(|| {
                invalid_arc_oauth_authorization_profile(
                    &row.receipt_id,
                    "proofRequired requires senderConstraint.proofSchema",
                )
            })?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "senderConstraint.proofSchema",
            proof_schema,
        )?;
    }

    Ok(())
}

fn chain_is_complete(capability_id: &str, chain: &[arc_kernel::CapabilitySnapshot]) -> bool {
    if chain.is_empty() {
        return false;
    }
    let Some(leaf) = chain.last() else {
        return false;
    };
    if leaf.capability_id != capability_id {
        return false;
    }
    if chain
        .first()
        .and_then(|snapshot| snapshot.parent_capability_id.as_ref())
        .is_some()
    {
        return false;
    }
    if chain.windows(2).any(|window| {
        window[1].parent_capability_id.as_deref() != Some(window[0].capability_id.as_str())
    }) {
        return false;
    }
    if leaf.parent_capability_id.is_some() && chain.len() == 1 {
        return false;
    }
    if leaf.delegation_depth as usize != chain.len().saturating_sub(1) {
        return false;
    }
    true
}

fn ratio_option(numerator: u64, denominator: u64) -> Option<f64> {
    if denominator == 0 {
        None
    } else {
        Some(numerator as f64 / denominator as f64)
    }
}

fn compliance_export_scope_note(
    query: &OperatorReportQuery,
    export_query: &EvidenceExportQuery,
) -> Option<String> {
    let mut notes = Vec::new();

    if !query.direct_evidence_export_supported() {
        notes.push(
            "tool filters narrow the operator report only; direct evidence export can scope by capability, agent, and time window".to_string(),
        );
    }

    match export_query.child_receipt_scope() {
        EvidenceChildReceiptScope::TimeWindowContextOnly => notes.push(
            "child receipts are included only as time-window context for this export scope".to_string(),
        ),
        EvidenceChildReceiptScope::OmittedNoJoinPath => notes.push(
            "child receipts are omitted for this export scope because no truthful capability/agent join exists yet".to_string(),
        ),
        EvidenceChildReceiptScope::FullQueryWindow => {}
    }

    if notes.is_empty() {
        None
    } else {
        Some(notes.join(" "))
    }
}

fn ensure_tool_receipt_attribution_columns(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(arc_tool_receipts)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let columns = columns.collect::<Result<Vec<_>, _>>()?;

    if !columns.iter().any(|column| column == "subject_key") {
        connection.execute(
            "ALTER TABLE arc_tool_receipts ADD COLUMN subject_key TEXT",
            [],
        )?;
    }
    if !columns.iter().any(|column| column == "issuer_key") {
        connection.execute(
            "ALTER TABLE arc_tool_receipts ADD COLUMN issuer_key TEXT",
            [],
        )?;
    }
    if !columns.iter().any(|column| column == "grant_index") {
        connection.execute(
            "ALTER TABLE arc_tool_receipts ADD COLUMN grant_index INTEGER",
            [],
        )?;
    }

    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_arc_tool_receipts_subject ON arc_tool_receipts(subject_key)",
        [],
    )?;
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_arc_tool_receipts_grant ON arc_tool_receipts(capability_id, grant_index)",
        [],
    )?;
    Ok(())
}

fn backfill_tool_receipt_attribution_columns(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    connection.execute_batch(
        r#"
        UPDATE arc_tool_receipts
        SET grant_index = CAST(COALESCE(
            json_extract(raw_json, '$.metadata.attribution.grant_index'),
            json_extract(raw_json, '$.metadata.financial.grant_index')
        ) AS INTEGER)
        WHERE grant_index IS NULL
          AND COALESCE(
                json_extract(raw_json, '$.metadata.attribution.grant_index'),
                json_extract(raw_json, '$.metadata.financial.grant_index')
              ) IS NOT NULL;

        UPDATE arc_tool_receipts
        SET subject_key = COALESCE(
            subject_key,
            CAST(json_extract(raw_json, '$.metadata.attribution.subject_key') AS TEXT),
            (SELECT cl.subject_key FROM capability_lineage cl WHERE cl.capability_id = arc_tool_receipts.capability_id)
        )
        WHERE subject_key IS NULL;

        UPDATE arc_tool_receipts
        SET issuer_key = COALESCE(
            issuer_key,
            CAST(json_extract(raw_json, '$.metadata.attribution.issuer_key') AS TEXT),
            (SELECT cl.issuer_key FROM capability_lineage cl WHERE cl.capability_id = arc_tool_receipts.capability_id)
        )
        WHERE issuer_key IS NULL;
        "#,
    )?;
    Ok(())
}

impl ReceiptStore for SqliteReceiptStore {
    fn append_arc_receipt(&mut self, receipt: &ArcReceipt) -> Result<(), ReceiptStoreError> {
        let raw_json = serde_json::to_string(receipt)?;
        let attribution = extract_receipt_attribution(receipt);
        self.connection.execute(
            r#"
            INSERT INTO arc_tool_receipts (
                receipt_id,
                timestamp,
                capability_id,
                subject_key,
                issuer_key,
                grant_index,
                tool_server,
                tool_name,
                decision_kind,
                policy_hash,
                content_hash,
                raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(receipt_id) DO NOTHING
            "#,
            params![
                receipt.id,
                receipt.timestamp,
                receipt.capability_id,
                attribution.subject_key,
                attribution.issuer_key,
                attribution.grant_index.map(i64::from),
                receipt.tool_server,
                receipt.tool_name,
                decision_kind(&receipt.decision),
                receipt.policy_hash,
                receipt.content_hash,
                raw_json,
            ],
        )?;
        Ok(())
    }

    fn append_arc_receipt_returning_seq(
        &mut self,
        receipt: &ArcReceipt,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        Ok(Some(SqliteReceiptStore::append_arc_receipt_returning_seq(
            self, receipt,
        )?))
    }

    fn receipts_canonical_bytes_range(
        &self,
        start_seq: u64,
        end_seq: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>, ReceiptStoreError> {
        SqliteReceiptStore::receipts_canonical_bytes_range(self, start_seq, end_seq)
    }

    fn store_checkpoint(&mut self, checkpoint: &KernelCheckpoint) -> Result<(), ReceiptStoreError> {
        SqliteReceiptStore::store_checkpoint(self, checkpoint)
    }

    fn record_capability_snapshot(
        &mut self,
        token: &CapabilityToken,
        parent_capability_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        SqliteReceiptStore::record_capability_snapshot(self, token, parent_capability_id).map_err(
            |error| match error {
                arc_kernel::CapabilityLineageError::Sqlite(error) => {
                    ReceiptStoreError::Sqlite(error)
                }
                arc_kernel::CapabilityLineageError::Json(error) => ReceiptStoreError::Json(error),
            },
        )
    }

    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        Some(self)
    }

    fn resolve_credit_bond(
        &self,
        bond_id: &str,
    ) -> Result<Option<CreditBondRow>, ReceiptStoreError> {
        self.query_credit_bonds(&CreditBondListQuery {
            bond_id: Some(bond_id.to_string()),
            facility_id: None,
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            disposition: None,
            lifecycle_state: None,
            limit: Some(1),
        })
        .map(|report| report.bonds.into_iter().next())
    }

    fn append_child_receipt(
        &mut self,
        receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        let raw_json = serde_json::to_string(receipt)?;
        self.connection.execute(
            r#"
            INSERT INTO arc_child_receipts (
                receipt_id,
                timestamp,
                session_id,
                parent_request_id,
                request_id,
                operation_kind,
                terminal_state,
                policy_hash,
                outcome_hash,
                raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(receipt_id) DO NOTHING
            "#,
            params![
                receipt.id,
                receipt.timestamp,
                receipt.session_id.as_str(),
                receipt.parent_request_id.as_str(),
                receipt.request_id.as_str(),
                receipt.operation_kind.as_str(),
                terminal_state_kind(&receipt.terminal_state),
                receipt.policy_hash,
                receipt.outcome_hash,
                raw_json,
            ],
        )?;
        Ok(())
    }
}

fn decision_kind(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Deny { .. } => "deny",
        Decision::Cancelled { .. } => "cancelled",
        Decision::Incomplete { .. } => "incomplete",
    }
}

fn terminal_state_kind(state: &OperationTerminalState) -> &'static str {
    match state {
        OperationTerminalState::Completed => "completed",
        OperationTerminalState::Cancelled { .. } => "cancelled",
        OperationTerminalState::Incomplete { .. } => "incomplete",
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use arc_core::capability::{
        ArcScope, CapabilityToken, CapabilityTokenBody, MonetaryAmount, Operation, ToolGrant,
    };
    use arc_core::crypto::Keypair;
    use arc_core::receipt::{
        ArcReceipt, ArcReceiptBody, ChildRequestReceipt, ChildRequestReceiptBody, Decision,
        FinancialReceiptMetadata, ReceiptAttributionMetadata, SettlementStatus, ToolCallAction,
    };
    use arc_core::session::{OperationKind, OperationTerminalState, RequestId, SessionId};
    use arc_kernel::{build_checkpoint, AnalyticsTimeBucket, ReceiptAnalyticsQuery};

    use super::*;

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    fn sample_receipt() -> ArcReceipt {
        let keypair = Keypair::generate();
        ArcReceipt::sign(
            ArcReceiptBody {
                id: "rcpt-test-001".to_string(),
                timestamp: 1,
                capability_id: "cap-1".to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action: ToolCallAction {
                    parameters: serde_json::json!({}),
                    parameter_hash: "abc123".to_string(),
                },
                decision: Decision::Allow,
                content_hash: "content-1".to_string(),
                policy_hash: "policy-1".to_string(),
                evidence: Vec::new(),
                metadata: None,
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )
        .unwrap()
    }

    fn sample_child_receipt() -> ChildRequestReceipt {
        let keypair = Keypair::generate();
        ChildRequestReceipt::sign(
            ChildRequestReceiptBody {
                id: "child-rcpt-test-001".to_string(),
                timestamp: 2,
                session_id: SessionId::new("sess-1"),
                parent_request_id: RequestId::new("parent-1"),
                request_id: RequestId::new("child-1"),
                operation_kind: OperationKind::CreateMessage,
                terminal_state: OperationTerminalState::Completed,
                outcome_hash: "outcome-1".to_string(),
                policy_hash: "policy-1".to_string(),
                metadata: None,
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )
        .unwrap()
    }

    #[test]
    fn sqlite_receipt_store_persists_across_reopen() {
        let path = unique_db_path("arc-receipts");
        {
            let mut store = SqliteReceiptStore::open(&path).unwrap();
            store.append_arc_receipt(&sample_receipt()).unwrap();
            store.append_child_receipt(&sample_child_receipt()).unwrap();
            assert_eq!(store.tool_receipt_count().unwrap(), 1);
            assert_eq!(store.child_receipt_count().unwrap(), 1);
        }

        let reopened = SqliteReceiptStore::open(&path).unwrap();
        assert_eq!(reopened.tool_receipt_count().unwrap(), 1);
        assert_eq!(reopened.child_receipt_count().unwrap(), 1);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn sqlite_receipt_store_lists_filtered_receipts() {
        let path = unique_db_path("arc-receipts-filtered");
        let mut store = SqliteReceiptStore::open(&path).unwrap();

        store.append_arc_receipt(&sample_receipt()).unwrap();
        store.append_child_receipt(&sample_child_receipt()).unwrap();

        let tool_receipts = store
            .list_tool_receipts(
                10,
                Some("cap-1"),
                Some("shell"),
                Some("bash"),
                Some("allow"),
            )
            .unwrap();
        assert_eq!(tool_receipts.len(), 1);
        assert_eq!(tool_receipts[0].capability_id, "cap-1");
        assert_eq!(tool_receipts[0].tool_name, "bash");

        let child_receipts = store
            .list_child_receipts(
                10,
                Some("sess-1"),
                Some("parent-1"),
                Some("child-1"),
                Some("create_message"),
                Some("completed"),
            )
            .unwrap();
        assert_eq!(child_receipts.len(), 1);
        assert_eq!(child_receipts[0].session_id.as_str(), "sess-1");
        assert_eq!(child_receipts[0].request_id.as_str(), "child-1");

        let _ = fs::remove_file(path);
    }

    fn sample_receipt_with_id(id: &str) -> ArcReceipt {
        let keypair = Keypair::generate();
        ArcReceipt::sign(
            ArcReceiptBody {
                id: id.to_string(),
                timestamp: 1,
                capability_id: "cap-1".to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action: ToolCallAction {
                    parameters: serde_json::json!({}),
                    parameter_hash: "abc123".to_string(),
                },
                decision: Decision::Allow,
                content_hash: "content-1".to_string(),
                policy_hash: "policy-1".to_string(),
                evidence: Vec::new(),
                metadata: None,
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )
        .unwrap()
    }

    #[test]
    fn open_creates_kernel_checkpoints_table() {
        let path = unique_db_path("arc-receipts-cp-table");
        let store = SqliteReceiptStore::open(&path).unwrap();
        // Query the table to confirm it exists.
        let count: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM kernel_checkpoints", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn append_arc_receipt_returning_seq_returns_seq() {
        let path = unique_db_path("arc-receipts-seq");
        let mut store = SqliteReceiptStore::open(&path).unwrap();
        let receipt = sample_receipt_with_id("rcpt-seq-001");
        let seq = store.append_arc_receipt_returning_seq(&receipt).unwrap();
        assert!(seq > 0, "seq should be non-zero for a new insert");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn append_100_receipts_seqs_span_1_to_100() {
        let path = unique_db_path("arc-receipts-100");
        let mut store = SqliteReceiptStore::open(&path).unwrap();
        let mut seqs = Vec::new();
        for i in 0..100usize {
            let receipt = sample_receipt_with_id(&format!("rcpt-{i:04}"));
            let seq = store.append_arc_receipt_returning_seq(&receipt).unwrap();
            seqs.push(seq);
        }
        assert_eq!(seqs[0], 1);
        assert_eq!(seqs[99], 100);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn store_and_load_checkpoint_by_seq() {
        let path = unique_db_path("arc-receipts-cp-store");
        let mut store = SqliteReceiptStore::open(&path).unwrap();

        // Append 5 receipts.
        let mut seqs = Vec::new();
        for i in 0..5usize {
            let receipt = sample_receipt_with_id(&format!("rcpt-store-{i}"));
            let seq = store.append_arc_receipt_returning_seq(&receipt).unwrap();
            seqs.push(seq);
        }

        // Build checkpoint.
        let kp = Keypair::generate();
        let bytes: Vec<Vec<u8>> = (0..5)
            .map(|i| format!("receipt-bytes-{i}").into_bytes())
            .collect();
        let cp = build_checkpoint(1, seqs[0], seqs[4], &bytes, &kp).unwrap();

        // Store and retrieve.
        store.store_checkpoint(&cp).unwrap();
        let loaded = store.load_checkpoint_by_seq(1).unwrap();
        assert!(loaded.is_some(), "checkpoint should be loadable");
        let loaded = loaded.unwrap();
        assert_eq!(loaded.body.checkpoint_seq, 1);
        assert_eq!(loaded.body.tree_size, 5);
        assert_eq!(loaded.body.batch_start_seq, seqs[0]);
        assert_eq!(loaded.body.batch_end_seq, seqs[4]);
        assert_eq!(
            loaded.signature.to_hex(),
            cp.signature.to_hex(),
            "signature should round-trip"
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_checkpoint_by_seq_returns_none_for_missing() {
        let path = unique_db_path("arc-receipts-cp-missing");
        let store = SqliteReceiptStore::open(&path).unwrap();
        let result = store.load_checkpoint_by_seq(999).unwrap();
        assert!(result.is_none());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn receipts_canonical_bytes_range_returns_correct_count() {
        let path = unique_db_path("arc-receipts-canon-range");
        let mut store = SqliteReceiptStore::open(&path).unwrap();

        for i in 0..10usize {
            let receipt = sample_receipt_with_id(&format!("rcpt-canon-{i}"));
            store.append_arc_receipt_returning_seq(&receipt).unwrap();
        }

        // Fetch seqs 3..=7 (5 receipts).
        let range = store.receipts_canonical_bytes_range(3, 7).unwrap();
        assert_eq!(range.len(), 5, "should return 5 receipts in range 3..=7");
        assert_eq!(range[0].0, 3);
        assert_eq!(range[4].0, 7);

        // Verify all bytes are non-empty canonical JSON.
        for (_, bytes) in &range {
            assert!(!bytes.is_empty());
            // Should be valid JSON.
            let _: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        }

        let _ = fs::remove_file(path);
    }

    #[test]
    fn receipt_analytics_groups_by_agent_tool_and_time() {
        let path = unique_db_path("arc-receipts-analytics");
        let mut store = SqliteReceiptStore::open(&path).unwrap();
        let keypair = Keypair::generate();

        let make_receipt = |id: &str,
                            subject_key: &str,
                            tool_server: &str,
                            tool_name: &str,
                            decision: Decision,
                            timestamp: u64,
                            cost_charged: u64,
                            attempted_cost: Option<u64>| {
            let financial = if cost_charged > 0 || attempted_cost.is_some() {
                Some(FinancialReceiptMetadata {
                    grant_index: 0,
                    cost_charged,
                    currency: "USD".to_string(),
                    budget_remaining: 1_000,
                    budget_total: 2_000,
                    delegation_depth: 0,
                    root_budget_holder: "root-agent".to_string(),
                    payment_reference: None,
                    settlement_status: if attempted_cost.is_some() {
                        SettlementStatus::NotApplicable
                    } else {
                        SettlementStatus::Settled
                    },
                    cost_breakdown: None,
                    attempted_cost,
                })
            } else {
                None
            };
            let metadata = serde_json::json!({
                "attribution": ReceiptAttributionMetadata {
                    subject_key: subject_key.to_string(),
                    issuer_key: "issuer-key".to_string(),
                    delegation_depth: 0,
                    grant_index: Some(0),
                },
                "financial": financial,
            });

            ArcReceipt::sign(
                ArcReceiptBody {
                    id: id.to_string(),
                    timestamp,
                    capability_id: format!("cap-{subject_key}"),
                    tool_server: tool_server.to_string(),
                    tool_name: tool_name.to_string(),
                    action: ToolCallAction {
                        parameters: serde_json::json!({}),
                        parameter_hash: "abc123".to_string(),
                    },
                    decision,
                    content_hash: format!("content-{id}"),
                    policy_hash: "policy-analytics".to_string(),
                    evidence: Vec::new(),
                    metadata: Some(metadata),
                    kernel_key: keypair.public_key(),
                },
                &keypair,
            )
            .unwrap()
        };

        store
            .append_arc_receipt(&make_receipt(
                "analytics-1",
                "agent-a",
                "shell",
                "bash",
                Decision::Allow,
                86_400,
                100,
                None,
            ))
            .unwrap();
        store
            .append_arc_receipt(&make_receipt(
                "analytics-2",
                "agent-a",
                "shell",
                "bash",
                Decision::Deny {
                    reason: "budget".to_string(),
                    guard: "kernel".to_string(),
                },
                86_450,
                0,
                Some(50),
            ))
            .unwrap();
        store
            .append_arc_receipt(&make_receipt(
                "analytics-3",
                "agent-b",
                "files",
                "read",
                Decision::Incomplete {
                    reason: "stream ended".to_string(),
                },
                172_800,
                0,
                None,
            ))
            .unwrap();

        let analytics = store
            .query_receipt_analytics(&ReceiptAnalyticsQuery {
                group_limit: Some(10),
                time_bucket: Some(AnalyticsTimeBucket::Day),
                ..ReceiptAnalyticsQuery::default()
            })
            .unwrap();

        assert_eq!(analytics.summary.total_receipts, 3);
        assert_eq!(analytics.summary.allow_count, 1);
        assert_eq!(analytics.summary.deny_count, 1);
        assert_eq!(analytics.summary.incomplete_count, 1);
        assert_eq!(analytics.summary.total_cost_charged, 100);
        assert_eq!(analytics.summary.total_attempted_cost, 50);
        assert_eq!(
            analytics.summary.reliability_score,
            Some(0.5),
            "allow / (allow + incomplete)"
        );
        assert_eq!(
            analytics.summary.compliance_rate,
            Some(2.0 / 3.0),
            "1 - deny / total"
        );
        assert_eq!(
            analytics.summary.budget_utilization_rate,
            Some(100.0 / 150.0)
        );

        assert_eq!(analytics.by_agent.len(), 2);
        assert_eq!(analytics.by_agent[0].subject_key, "agent-a");
        assert_eq!(analytics.by_agent[0].metrics.total_receipts, 2);

        assert_eq!(analytics.by_tool.len(), 2);
        assert_eq!(analytics.by_tool[0].tool_server, "shell");
        assert_eq!(analytics.by_tool[0].tool_name, "bash");
        assert_eq!(analytics.by_tool[0].metrics.total_receipts, 2);

        assert_eq!(analytics.by_time.len(), 2);
        assert_eq!(analytics.by_time[0].bucket_start, 86_400);
        assert_eq!(analytics.by_time[1].bucket_start, 172_800);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn cost_attribution_report_aggregates_matching_corpus_and_limits_detail_rows() {
        let path = unique_db_path("arc-receipts-cost-attribution");
        let mut store = SqliteReceiptStore::open(&path).unwrap();
        let issuer_kp = Keypair::generate();
        let root_kp = Keypair::generate();
        let leaf_kp = Keypair::generate();
        let receipt_kp = Keypair::generate();
        let root_hex = root_kp.public_key().to_hex();
        let leaf_hex = leaf_kp.public_key().to_hex();
        let issuer_hex = issuer_kp.public_key().to_hex();

        let root = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-root".to_string(),
                issuer: issuer_kp.public_key(),
                subject: root_kp.public_key(),
                scope: ArcScope::default(),
                issued_at: 1_000,
                expires_at: 9_000,
                delegation_chain: vec![],
            },
            &issuer_kp,
        )
        .unwrap();
        let child = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-child".to_string(),
                issuer: issuer_kp.public_key(),
                subject: leaf_kp.public_key(),
                scope: ArcScope::default(),
                issued_at: 1_100,
                expires_at: 9_000,
                delegation_chain: vec![],
            },
            &issuer_kp,
        )
        .unwrap();

        store.record_capability_snapshot(&root, None).unwrap();
        store
            .record_capability_snapshot(&child, Some("cap-root"))
            .unwrap();

        let make_financial_receipt =
            |id: &str,
             capability_id: &str,
             subject_key: Option<String>,
             root_budget_holder: &str,
             delegation_depth: u32,
             timestamp: u64,
             decision: Decision,
             cost_charged: u64,
             attempted_cost: Option<u64>| {
                let attribution = subject_key.map(|subject_key| ReceiptAttributionMetadata {
                    subject_key,
                    issuer_key: issuer_hex.clone(),
                    delegation_depth,
                    grant_index: Some(0),
                });
                let metadata = serde_json::json!({
                    "attribution": attribution,
                    "financial": FinancialReceiptMetadata {
                        grant_index: 0,
                        cost_charged,
                        currency: "USD".to_string(),
                        budget_remaining: 900,
                        budget_total: 1_000,
                        delegation_depth,
                        root_budget_holder: root_budget_holder.to_string(),
                        payment_reference: None,
                        settlement_status: if attempted_cost.is_some() && cost_charged == 0 {
                            SettlementStatus::NotApplicable
                        } else {
                            SettlementStatus::Settled
                        },
                        cost_breakdown: None,
                        attempted_cost,
                    }
                });

                ArcReceipt::sign(
                    ArcReceiptBody {
                        id: id.to_string(),
                        timestamp,
                        capability_id: capability_id.to_string(),
                        tool_server: "shell".to_string(),
                        tool_name: "bash".to_string(),
                        action: ToolCallAction {
                            parameters: serde_json::json!({}),
                            parameter_hash: format!("param-{id}"),
                        },
                        decision,
                        content_hash: format!("content-{id}"),
                        policy_hash: "policy-cost".to_string(),
                        evidence: Vec::new(),
                        metadata: Some(metadata),
                        kernel_key: receipt_kp.public_key(),
                    },
                    &receipt_kp,
                )
                .unwrap()
            };

        store
            .append_arc_receipt(&make_financial_receipt(
                "cost-1",
                "cap-child",
                Some(leaf_hex.clone()),
                &root_hex,
                1,
                1_200,
                Decision::Allow,
                125,
                None,
            ))
            .unwrap();
        store
            .append_arc_receipt(&make_financial_receipt(
                "cost-2",
                "cap-child",
                Some(leaf_hex.clone()),
                &root_hex,
                1,
                1_201,
                Decision::Deny {
                    reason: "budget".to_string(),
                    guard: "kernel".to_string(),
                },
                0,
                Some(75),
            ))
            .unwrap();
        store
            .append_arc_receipt(&make_financial_receipt(
                "cost-3",
                "cap-orphan",
                None,
                "orphan-root",
                2,
                1_202,
                Decision::Allow,
                50,
                None,
            ))
            .unwrap();

        let report = store
            .query_cost_attribution_report(&CostAttributionQuery {
                limit: Some(1),
                ..CostAttributionQuery::default()
            })
            .unwrap();

        assert_eq!(report.summary.matching_receipts, 3);
        assert_eq!(report.summary.returned_receipts, 1);
        assert_eq!(report.summary.total_cost_charged, 175);
        assert_eq!(report.summary.total_attempted_cost, 75);
        assert_eq!(report.summary.max_delegation_depth, 2);
        assert_eq!(report.summary.distinct_root_subjects, 2);
        assert_eq!(report.summary.distinct_leaf_subjects, 1);
        assert_eq!(report.summary.lineage_gap_count, 1);
        assert!(report.summary.truncated);

        assert_eq!(report.by_root.len(), 2);
        assert_eq!(
            report.by_root[0].root_subject_key.as_str(),
            root_hex.as_str()
        );
        assert_eq!(report.by_root[0].receipt_count, 2);
        assert_eq!(report.by_root[0].total_cost_charged, 125);
        assert_eq!(report.by_root[0].total_attempted_cost, 75);
        assert_eq!(report.by_root[0].distinct_leaf_subjects, 1);

        assert_eq!(report.by_leaf.len(), 1);
        assert_eq!(
            report.by_leaf[0].root_subject_key.as_str(),
            root_hex.as_str()
        );
        assert_eq!(
            report.by_leaf[0].leaf_subject_key.as_str(),
            leaf_hex.as_str()
        );
        assert_eq!(report.by_leaf[0].receipt_count, 2);
        assert_eq!(report.by_leaf[0].total_cost_charged, 125);
        assert_eq!(report.by_leaf[0].total_attempted_cost, 75);

        assert_eq!(report.receipts.len(), 1);
        assert_eq!(report.receipts[0].capability_id, "cap-child");
        assert_eq!(
            report.receipts[0].root_subject_key.as_deref(),
            Some(root_hex.as_str())
        );
        assert_eq!(
            report.receipts[0].leaf_subject_key.as_deref(),
            Some(leaf_hex.as_str())
        );
        assert!(report.receipts[0].lineage_complete);
        assert_eq!(report.receipts[0].chain.len(), 2);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn compliance_report_counts_proof_and_lineage_coverage_truthfully() {
        let path = unique_db_path("arc-receipts-compliance");
        let mut store = SqliteReceiptStore::open(&path).unwrap();
        let issuer_kp = Keypair::generate();
        let subject_kp = Keypair::generate();
        let checkpoint_kp = Keypair::generate();
        let subject_hex = subject_kp.public_key().to_hex();
        let issuer_hex = issuer_kp.public_key().to_hex();

        let token = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-compliance".to_string(),
                issuer: issuer_kp.public_key(),
                subject: subject_kp.public_key(),
                scope: ArcScope {
                    grants: vec![ToolGrant {
                        server_id: "shell".to_string(),
                        tool_name: "bash".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: Some(4),
                        max_cost_per_invocation: Some(MonetaryAmount {
                            units: 500,
                            currency: "USD".to_string(),
                        }),
                        max_total_cost: Some(MonetaryAmount {
                            units: 1000,
                            currency: "USD".to_string(),
                        }),
                        dpop_required: None,
                    }],
                    resource_grants: vec![],
                    prompt_grants: vec![],
                },
                issued_at: 1_000,
                expires_at: 9_000,
                delegation_chain: vec![],
            },
            &issuer_kp,
        )
        .unwrap();
        store.record_capability_snapshot(&token, None).unwrap();

        let make_receipt = |id: &str,
                            timestamp: u64,
                            decision: Decision,
                            settlement_status: SettlementStatus,
                            attempted_cost: Option<u64>| {
            let metadata = serde_json::json!({
                "attribution": ReceiptAttributionMetadata {
                    subject_key: subject_hex.clone(),
                    issuer_key: issuer_hex.clone(),
                    delegation_depth: 0,
                    grant_index: Some(0),
                },
                "financial": FinancialReceiptMetadata {
                    grant_index: 0,
                    cost_charged: if attempted_cost.is_some() { 0 } else { 250 },
                    currency: "USD".to_string(),
                    budget_remaining: 750,
                    budget_total: 1000,
                    delegation_depth: 0,
                    root_budget_holder: subject_hex.clone(),
                    payment_reference: None,
                    settlement_status,
                    cost_breakdown: None,
                    attempted_cost,
                }
            });

            ArcReceipt::sign(
                ArcReceiptBody {
                    id: id.to_string(),
                    timestamp,
                    capability_id: "cap-compliance".to_string(),
                    tool_server: "shell".to_string(),
                    tool_name: "bash".to_string(),
                    action: ToolCallAction {
                        parameters: serde_json::json!({}),
                        parameter_hash: format!("param-{id}"),
                    },
                    decision,
                    content_hash: format!("content-{id}"),
                    policy_hash: "policy-compliance".to_string(),
                    evidence: Vec::new(),
                    metadata: Some(metadata),
                    kernel_key: checkpoint_kp.public_key(),
                },
                &checkpoint_kp,
            )
            .unwrap()
        };

        let seq = store
            .append_arc_receipt_returning_seq(&make_receipt(
                "compliance-1",
                2_000,
                Decision::Allow,
                SettlementStatus::Settled,
                None,
            ))
            .unwrap();
        store
            .append_arc_receipt(&make_receipt(
                "compliance-2",
                2_001,
                Decision::Deny {
                    reason: "budget".to_string(),
                    guard: "kernel".to_string(),
                },
                SettlementStatus::Pending,
                Some(100),
            ))
            .unwrap();

        let bytes = store
            .receipts_canonical_bytes_range(seq, seq)
            .unwrap()
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect::<Vec<_>>();
        let checkpoint = build_checkpoint(1, seq, seq, &bytes, &checkpoint_kp).unwrap();
        store.store_checkpoint(&checkpoint).unwrap();

        let report = store
            .query_compliance_report(&OperatorReportQuery {
                agent_subject: Some(subject_hex.clone()),
                tool_server: Some("shell".to_string()),
                tool_name: Some("bash".to_string()),
                ..OperatorReportQuery::default()
            })
            .unwrap();

        assert_eq!(report.matching_receipts, 2);
        assert_eq!(report.evidence_ready_receipts, 1);
        assert_eq!(report.uncheckpointed_receipts, 1);
        assert_eq!(report.lineage_covered_receipts, 2);
        assert_eq!(report.lineage_gap_receipts, 0);
        assert_eq!(report.pending_settlement_receipts, 1);
        assert_eq!(report.failed_settlement_receipts, 0);
        assert!(!report.direct_evidence_export_supported);
        assert_eq!(
            report.child_receipt_scope,
            crate::EvidenceChildReceiptScope::OmittedNoJoinPath
        );
        assert!(report
            .export_scope_note
            .as_deref()
            .is_some_and(|note| note.contains("tool filters narrow the operator report only")));

        let _ = fs::remove_file(path);
    }
}
