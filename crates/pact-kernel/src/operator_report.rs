use serde::{Deserialize, Serialize};

use crate::cost_attribution::CostAttributionQuery;
use crate::evidence_export::{EvidenceChildReceiptScope, EvidenceExportQuery};
use crate::receipt_analytics::{AnalyticsTimeBucket, ReceiptAnalyticsResponse};
use crate::receipt_store::FederatedEvidenceShareSummary;
use crate::CostAttributionReport;

/// Maximum number of budget rows returned in a single operator report.
pub const MAX_OPERATOR_BUDGET_LIMIT: usize = 200;
/// Maximum number of shared-evidence reference rows returned in one query.
pub const MAX_SHARED_EVIDENCE_LIMIT: usize = 200;

/// Filter surface for the operator-facing reporting API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OperatorReportQuery {
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
    pub group_limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_bucket: Option<AnalyticsTimeBucket>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribution_limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_limit: Option<usize>,
}

impl Default for OperatorReportQuery {
    fn default() -> Self {
        Self {
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            since: None,
            until: None,
            group_limit: Some(50),
            time_bucket: Some(AnalyticsTimeBucket::Day),
            attribution_limit: Some(100),
            budget_limit: Some(50),
        }
    }
}

impl OperatorReportQuery {
    #[must_use]
    pub fn to_receipt_analytics_query(&self) -> crate::ReceiptAnalyticsQuery {
        crate::ReceiptAnalyticsQuery {
            capability_id: self.capability_id.clone(),
            agent_subject: self.agent_subject.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            since: self.since,
            until: self.until,
            group_limit: self.group_limit,
            time_bucket: self.time_bucket,
        }
    }

    #[must_use]
    pub fn to_cost_attribution_query(&self) -> CostAttributionQuery {
        CostAttributionQuery {
            capability_id: self.capability_id.clone(),
            agent_subject: self.agent_subject.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            since: self.since,
            until: self.until,
            limit: self.attribution_limit,
        }
    }

    #[must_use]
    pub fn to_evidence_export_query(&self) -> EvidenceExportQuery {
        EvidenceExportQuery {
            capability_id: self.capability_id.clone(),
            agent_subject: self.agent_subject.clone(),
            since: self.since,
            until: self.until,
        }
    }

    #[must_use]
    pub fn direct_evidence_export_supported(&self) -> bool {
        self.tool_server.is_none() && self.tool_name.is_none()
    }

    #[must_use]
    pub fn budget_limit_or_default(&self) -> usize {
        self.budget_limit
            .unwrap_or(50)
            .clamp(1, MAX_OPERATOR_BUDGET_LIMIT)
    }

    #[must_use]
    pub fn to_shared_evidence_query(&self) -> SharedEvidenceQuery {
        SharedEvidenceQuery {
            capability_id: self.capability_id.clone(),
            agent_subject: self.agent_subject.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            since: self.since,
            until: self.until,
            issuer: None,
            partner: None,
            limit: self.group_limit,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SharedEvidenceQuery {
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
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl Default for SharedEvidenceQuery {
    fn default() -> Self {
        Self {
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            since: None,
            until: None,
            issuer: None,
            partner: None,
            limit: Some(50),
        }
    }
}

impl SharedEvidenceQuery {
    #[must_use]
    pub fn limit_or_default(&self) -> usize {
        self.limit.unwrap_or(50).clamp(1, MAX_SHARED_EVIDENCE_LIMIT)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BudgetUtilizationSummary {
    pub matching_grants: u64,
    pub returned_grants: u64,
    pub distinct_capabilities: u64,
    pub distinct_subjects: u64,
    pub total_invocations: u64,
    pub total_cost_charged: u64,
    pub near_limit_count: u64,
    pub exhausted_count: u64,
    pub rows_missing_scope: u64,
    pub rows_missing_lineage: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BudgetUtilizationRow {
    pub capability_id: String,
    pub grant_index: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    pub invocation_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_invocations: Option<u32>,
    pub total_cost_charged: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_cost_units: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining_cost_units: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invocation_utilization_rate: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_utilization_rate: Option<f64>,
    pub near_limit: bool,
    pub exhausted: bool,
    pub updated_at: i64,
    pub scope_resolved: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_resolution_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BudgetUtilizationReport {
    pub summary: BudgetUtilizationSummary,
    pub rows: Vec<BudgetUtilizationRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceReport {
    pub matching_receipts: u64,
    pub evidence_ready_receipts: u64,
    pub uncheckpointed_receipts: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_coverage_rate: Option<f64>,
    pub lineage_covered_receipts: u64,
    pub lineage_gap_receipts: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lineage_coverage_rate: Option<f64>,
    pub pending_settlement_receipts: u64,
    pub failed_settlement_receipts: u64,
    pub direct_evidence_export_supported: bool,
    pub child_receipt_scope: EvidenceChildReceiptScope,
    pub proofs_complete: bool,
    pub export_query: EvidenceExportQuery,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_scope_note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SharedEvidenceReferenceSummary {
    pub matching_shares: u64,
    pub matching_references: u64,
    pub matching_local_receipts: u64,
    pub remote_tool_receipts: u64,
    pub remote_lineage_records: u64,
    pub distinct_remote_subjects: u64,
    pub proof_required_shares: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SharedEvidenceReferenceRow {
    pub share: FederatedEvidenceShareSummary,
    pub capability_id: String,
    pub subject_key: String,
    pub issuer_key: String,
    pub delegation_depth: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_anchor_capability_id: Option<String>,
    pub matched_local_receipts: u64,
    pub allow_count: u64,
    pub deny_count: u64,
    pub cancelled_count: u64,
    pub incomplete_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SharedEvidenceReferenceReport {
    pub summary: SharedEvidenceReferenceSummary,
    pub references: Vec<SharedEvidenceReferenceRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OperatorReport {
    pub generated_at: u64,
    pub filters: OperatorReportQuery,
    pub activity: ReceiptAnalyticsResponse,
    pub cost_attribution: CostAttributionReport,
    pub budget_utilization: BudgetUtilizationReport,
    pub compliance: ComplianceReport,
    pub shared_evidence: SharedEvidenceReferenceReport,
}
