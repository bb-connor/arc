//! pact-reputation: deterministic local reputation scoring for PACT agents.
//!
//! This crate is intentionally pure and storage-agnostic. It scores an agent
//! from a caller-provided local corpus assembled from persisted receipts,
//! capability-lineage snapshots, and budget-usage records. It does not depend
//! on `pact-kernel`, which keeps the scoring model reusable and avoids a future
//! dependency cycle when kernel-side issuance hooks begin consuming it.

use std::collections::{BTreeMap, BTreeSet};

use pact_core::capability::{Operation, PactScope, ToolGrant};
use pact_core::receipt::{Decision, PactReceipt, ReceiptAttributionMetadata};
use serde::{Deserialize, Serialize};

const SECONDS_PER_DAY: u64 = 86_400;
const DEFAULT_HISTORY_RECEIPT_TARGET: u64 = 1_000;
const DEFAULT_HISTORY_DAY_TARGET: u64 = 30;
const DEFAULT_INCIDENT_PENALTY: f64 = 0.20;

#[derive(Debug, thiserror::Error)]
pub enum ReputationError {
    #[error("failed to decode capability scope json: {0}")]
    InvalidScopeJson(#[from] serde_json::Error),
}

/// Normalized local view of a persisted capability-lineage snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityLineageRecord {
    pub capability_id: String,
    pub subject_key: String,
    pub issuer_key: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub scope: PactScope,
    pub delegation_depth: u64,
    pub parent_capability_id: Option<String>,
}

impl CapabilityLineageRecord {
    pub fn from_scope_json(
        capability_id: impl Into<String>,
        subject_key: impl Into<String>,
        issuer_key: impl Into<String>,
        issued_at: u64,
        expires_at: u64,
        scope_json: &str,
        delegation_depth: u64,
        parent_capability_id: Option<String>,
    ) -> Result<Self, ReputationError> {
        Ok(Self {
            capability_id: capability_id.into(),
            subject_key: subject_key.into(),
            issuer_key: issuer_key.into(),
            issued_at,
            expires_at,
            scope: serde_json::from_str(scope_json)?,
            delegation_depth,
            parent_capability_id,
        })
    }
}

/// Normalized local view of per-grant budget usage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BudgetUsageRecord {
    pub capability_id: String,
    pub grant_index: u32,
    pub invocation_count: u32,
    pub updated_at: i64,
    pub total_cost_charged: u64,
}

/// Optional external incident data. `None` at the corpus level means the
/// incident metric is unavailable, not zero.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncidentRecord {
    pub timestamp: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalReputationCorpus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<PactReceipt>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<CapabilityLineageRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub budget_usage: Vec<BudgetUsageRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incident_reports: Option<Vec<IncidentRecord>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(tag = "state", content = "value", rename_all = "snake_case")]
pub enum MetricValue {
    Known(f64),
    Unknown,
}

impl MetricValue {
    fn known(value: f64) -> Self {
        Self::Known(clamp01(value))
    }

    #[must_use]
    pub fn as_option(self) -> Option<f64> {
        match self {
            Self::Known(value) => Some(value),
            Self::Unknown => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct ReputationWeights {
    pub boundary_pressure: f64,
    pub resource_stewardship: f64,
    pub least_privilege: f64,
    pub history_depth: f64,
    pub tool_diversity: f64,
    pub delegation_hygiene: f64,
    pub reliability: f64,
    pub incident_correlation: f64,
}

impl Default for ReputationWeights {
    fn default() -> Self {
        Self {
            boundary_pressure: 0.20,
            resource_stewardship: 0.10,
            least_privilege: 0.15,
            history_depth: 0.10,
            tool_diversity: 0.05,
            delegation_hygiene: 0.15,
            reliability: 0.15,
            incident_correlation: 0.10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReputationConfig {
    pub weights: ReputationWeights,
    pub target_utilization: f64,
    pub diversity_cap: f64,
    pub temporal_decay_half_life_days: u32,
    pub history_receipt_target: u64,
    pub history_day_target: u64,
    pub incident_penalty: f64,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            weights: ReputationWeights::default(),
            target_utilization: 0.75,
            diversity_cap: 1.0,
            temporal_decay_half_life_days: 30,
            history_receipt_target: DEFAULT_HISTORY_RECEIPT_TARGET,
            history_day_target: DEFAULT_HISTORY_DAY_TARGET,
            incident_penalty: DEFAULT_INCIDENT_PENALTY,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BoundaryPressureMetrics {
    pub deny_ratio: MetricValue,
    pub policies_observed: usize,
    pub receipts_observed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResourceStewardshipMetrics {
    pub average_utilization: MetricValue,
    pub fit_score: MetricValue,
    pub capped_grants_observed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LeastPrivilegeMetrics {
    pub score: MetricValue,
    pub capabilities_observed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoryDepthMetrics {
    pub score: MetricValue,
    pub receipt_count: usize,
    pub active_days: usize,
    pub first_seen: Option<u64>,
    pub last_seen: Option<u64>,
    pub span_days: u64,
    pub activity_ratio: MetricValue,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpecializationMetrics {
    pub score: MetricValue,
    pub distinct_tools: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DelegationHygieneMetrics {
    pub score: MetricValue,
    pub delegations_observed: usize,
    pub scope_reduction_rate: MetricValue,
    pub ttl_reduction_rate: MetricValue,
    pub budget_reduction_rate: MetricValue,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReliabilityMetrics {
    pub score: MetricValue,
    pub completion_rate: MetricValue,
    pub cancellation_rate: MetricValue,
    pub incompletion_rate: MetricValue,
    pub receipts_observed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IncidentCorrelationMetrics {
    pub score: MetricValue,
    pub incidents_observed: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LocalReputationScorecard {
    pub subject_key: String,
    pub computed_at: u64,
    pub boundary_pressure: BoundaryPressureMetrics,
    pub resource_stewardship: ResourceStewardshipMetrics,
    pub least_privilege: LeastPrivilegeMetrics,
    pub history_depth: HistoryDepthMetrics,
    pub specialization: SpecializationMetrics,
    pub delegation_hygiene: DelegationHygieneMetrics,
    pub reliability: ReliabilityMetrics,
    pub incident_correlation: IncidentCorrelationMetrics,
    pub composite_score: MetricValue,
    pub effective_weight_sum: f64,
}

/// Compute the local Phase 1 reputation scorecard for one agent.
#[must_use]
pub fn compute_local_scorecard(
    subject_key: &str,
    now: u64,
    corpus: &LocalReputationCorpus,
    config: &ReputationConfig,
) -> LocalReputationScorecard {
    let capability_map: BTreeMap<&str, &CapabilityLineageRecord> = corpus
        .capabilities
        .iter()
        .map(|record| (record.capability_id.as_str(), record))
        .collect();

    let subject_receipts: Vec<&PactReceipt> = corpus
        .receipts
        .iter()
        .filter(|receipt| {
            receipt_subject_key(receipt, &capability_map).as_deref() == Some(subject_key)
        })
        .collect();

    let subject_capabilities: Vec<&CapabilityLineageRecord> = corpus
        .capabilities
        .iter()
        .filter(|record| record.subject_key == subject_key)
        .collect();

    let delegations_issued: Vec<&CapabilityLineageRecord> = corpus
        .capabilities
        .iter()
        .filter(|record| record.issuer_key == subject_key && record.parent_capability_id.is_some())
        .collect();

    let boundary_pressure = compute_boundary_pressure(&subject_receipts, now, config);
    let resource_stewardship =
        compute_resource_stewardship(&subject_capabilities, &corpus.budget_usage, config);
    let least_privilege =
        compute_least_privilege(&subject_capabilities, &subject_receipts, now, config);
    let history_depth = compute_history_depth(&subject_receipts, config);
    let specialization = compute_specialization(&subject_receipts, now, config);
    let delegation_hygiene =
        compute_delegation_hygiene(&delegations_issued, &capability_map, now, config);
    let reliability = compute_reliability(&subject_receipts, now, config);
    let incident_correlation = compute_incident_correlation(subject_key, now, corpus, config);

    let mut weighted_sum = 0.0;
    let mut effective_weight_sum = 0.0;

    contribute_metric(
        boundary_pressure
            .deny_ratio
            .as_option()
            .map(|value| 1.0 - value),
        config.weights.boundary_pressure,
        &mut weighted_sum,
        &mut effective_weight_sum,
    );
    contribute_metric(
        resource_stewardship.fit_score.as_option(),
        config.weights.resource_stewardship,
        &mut weighted_sum,
        &mut effective_weight_sum,
    );
    contribute_metric(
        least_privilege.score.as_option(),
        config.weights.least_privilege,
        &mut weighted_sum,
        &mut effective_weight_sum,
    );
    contribute_metric(
        history_depth.score.as_option(),
        config.weights.history_depth,
        &mut weighted_sum,
        &mut effective_weight_sum,
    );
    contribute_metric(
        specialization
            .score
            .as_option()
            .map(|value| value.min(clamp01(config.diversity_cap))),
        config.weights.tool_diversity,
        &mut weighted_sum,
        &mut effective_weight_sum,
    );
    contribute_metric(
        delegation_hygiene.score.as_option(),
        config.weights.delegation_hygiene,
        &mut weighted_sum,
        &mut effective_weight_sum,
    );
    contribute_metric(
        reliability.score.as_option(),
        config.weights.reliability,
        &mut weighted_sum,
        &mut effective_weight_sum,
    );
    contribute_metric(
        incident_correlation.score.as_option(),
        config.weights.incident_correlation,
        &mut weighted_sum,
        &mut effective_weight_sum,
    );

    let composite_score = if effective_weight_sum > 0.0 {
        MetricValue::known(weighted_sum / effective_weight_sum)
    } else {
        MetricValue::Unknown
    };

    LocalReputationScorecard {
        subject_key: subject_key.to_string(),
        computed_at: now,
        boundary_pressure,
        resource_stewardship,
        least_privilege,
        history_depth,
        specialization,
        delegation_hygiene,
        reliability,
        incident_correlation,
        composite_score,
        effective_weight_sum,
    }
}

fn compute_boundary_pressure(
    receipts: &[&PactReceipt],
    now: u64,
    config: &ReputationConfig,
) -> BoundaryPressureMetrics {
    if receipts.is_empty() {
        return BoundaryPressureMetrics {
            deny_ratio: MetricValue::Unknown,
            policies_observed: 0,
            receipts_observed: 0,
        };
    }

    let mut by_policy: BTreeMap<&str, (f64, f64)> = BTreeMap::new();
    for receipt in receipts {
        let weight = decay_weight(now, receipt.timestamp, config.temporal_decay_half_life_days);
        let entry = by_policy
            .entry(receipt.policy_hash.as_str())
            .or_insert((0.0, 0.0));
        if matches!(receipt.decision, Decision::Deny { .. }) {
            entry.0 += weight;
        }
        entry.1 += weight;
    }

    let deny_ratio = by_policy
        .values()
        .map(|(denied, total)| if *total > 0.0 { denied / total } else { 0.0 })
        .sum::<f64>()
        / by_policy.len() as f64;

    BoundaryPressureMetrics {
        deny_ratio: MetricValue::known(deny_ratio),
        policies_observed: by_policy.len(),
        receipts_observed: receipts.len(),
    }
}

fn compute_resource_stewardship(
    capabilities: &[&CapabilityLineageRecord],
    budget_usage: &[BudgetUsageRecord],
    config: &ReputationConfig,
) -> ResourceStewardshipMetrics {
    let usage_index: BTreeMap<(&str, u32), &BudgetUsageRecord> = budget_usage
        .iter()
        .map(|record| ((record.capability_id.as_str(), record.grant_index), record))
        .collect();

    let mut utilizations = Vec::new();

    for capability in capabilities {
        for (grant_index, grant) in capability.scope.grants.iter().enumerate() {
            if let Some(max_invocations) = grant.max_invocations {
                if max_invocations == 0 {
                    continue;
                }
                let actual = usage_index
                    .get(&(capability.capability_id.as_str(), grant_index as u32))
                    .map(|record| record.invocation_count)
                    .unwrap_or(0);
                utilizations.push((actual as f64 / max_invocations as f64).min(1.0));
            }
        }
    }

    if utilizations.is_empty() {
        return ResourceStewardshipMetrics {
            average_utilization: MetricValue::Unknown,
            fit_score: MetricValue::Unknown,
            capped_grants_observed: 0,
        };
    }

    let average_utilization = utilizations.iter().sum::<f64>() / utilizations.len() as f64;
    let fit_score = 1.0 - (average_utilization - clamp01(config.target_utilization)).abs();

    ResourceStewardshipMetrics {
        average_utilization: MetricValue::known(average_utilization),
        fit_score: MetricValue::known(fit_score),
        capped_grants_observed: utilizations.len(),
    }
}

fn compute_least_privilege(
    capabilities: &[&CapabilityLineageRecord],
    receipts: &[&PactReceipt],
    now: u64,
    config: &ReputationConfig,
) -> LeastPrivilegeMetrics {
    let mut weighted_scores = Vec::new();

    for capability in capabilities {
        let grants = &capability.scope.grants;
        if grants.is_empty() {
            continue;
        }

        let used_tools: BTreeSet<(&str, &str)> = receipts
            .iter()
            .filter(|receipt| {
                receipt.capability_id == capability.capability_id
                    && matches!(receipt.decision, Decision::Allow)
            })
            .map(|receipt| (receipt.tool_server.as_str(), receipt.tool_name.as_str()))
            .collect();

        let base = used_tools.len() as f64 / grants.len() as f64;
        let constrained_ratio = grants
            .iter()
            .filter(|grant| !grant.constraints.is_empty())
            .count() as f64
            / grants.len() as f64;
        let non_delegate_ratio = grants
            .iter()
            .filter(|grant| !grant.operations.contains(&Operation::Delegate))
            .count() as f64
            / grants.len() as f64;

        let constraint_factor = 0.5 + 0.5 * constrained_ratio;
        let operation_factor = 0.5 + 0.5 * non_delegate_ratio;
        let score = clamp01(base * constraint_factor * operation_factor);
        let weight = decay_weight(
            now,
            capability.issued_at,
            config.temporal_decay_half_life_days,
        );
        weighted_scores.push((score, weight));
    }

    if weighted_scores.is_empty() {
        return LeastPrivilegeMetrics {
            score: MetricValue::Unknown,
            capabilities_observed: 0,
        };
    }

    LeastPrivilegeMetrics {
        score: MetricValue::known(weighted_average(&weighted_scores)),
        capabilities_observed: weighted_scores.len(),
    }
}

fn compute_history_depth(
    receipts: &[&PactReceipt],
    config: &ReputationConfig,
) -> HistoryDepthMetrics {
    if receipts.is_empty() {
        return HistoryDepthMetrics {
            score: MetricValue::Unknown,
            receipt_count: 0,
            active_days: 0,
            first_seen: None,
            last_seen: None,
            span_days: 0,
            activity_ratio: MetricValue::Unknown,
        };
    }

    let first_seen = receipts.iter().map(|receipt| receipt.timestamp).min();
    let last_seen = receipts.iter().map(|receipt| receipt.timestamp).max();
    let active_days: BTreeSet<u64> = receipts
        .iter()
        .map(|receipt| receipt.timestamp / SECONDS_PER_DAY)
        .collect();
    let span_days = match (first_seen, last_seen) {
        (Some(first), Some(last)) => ((last.saturating_sub(first)) / SECONDS_PER_DAY).max(1) + 1,
        _ => 0,
    };
    let activity_ratio = if span_days > 0 {
        active_days.len() as f64 / span_days as f64
    } else {
        0.0
    };
    let receipt_score =
        (receipts.len() as f64 / config.history_receipt_target.max(1) as f64).min(1.0);
    let day_score = (span_days as f64 / config.history_day_target.max(1) as f64).min(1.0);
    let normalized = (receipt_score + day_score + activity_ratio) / 3.0;

    HistoryDepthMetrics {
        score: MetricValue::known(normalized),
        receipt_count: receipts.len(),
        active_days: active_days.len(),
        first_seen,
        last_seen,
        span_days,
        activity_ratio: MetricValue::known(activity_ratio),
    }
}

fn compute_specialization(
    receipts: &[&PactReceipt],
    now: u64,
    config: &ReputationConfig,
) -> SpecializationMetrics {
    if receipts.is_empty() {
        return SpecializationMetrics {
            score: MetricValue::Unknown,
            distinct_tools: 0,
        };
    }

    let mut weights_by_tool: BTreeMap<(&str, &str), f64> = BTreeMap::new();
    for receipt in receipts {
        let weight = decay_weight(now, receipt.timestamp, config.temporal_decay_half_life_days);
        *weights_by_tool
            .entry((receipt.tool_server.as_str(), receipt.tool_name.as_str()))
            .or_default() += weight;
    }

    let total_weight = weights_by_tool.values().sum::<f64>();
    let entropy = weights_by_tool
        .values()
        .map(|count| {
            let p = count / total_weight;
            -p * p.log2()
        })
        .sum::<f64>();
    let max_entropy = if weights_by_tool.len() > 1 {
        (weights_by_tool.len() as f64).log2()
    } else {
        0.0
    };
    let score = if max_entropy > 0.0 {
        entropy / max_entropy
    } else {
        0.0
    };

    SpecializationMetrics {
        score: MetricValue::known(score),
        distinct_tools: weights_by_tool.len(),
    }
}

fn compute_delegation_hygiene(
    delegations: &[&CapabilityLineageRecord],
    capability_map: &BTreeMap<&str, &CapabilityLineageRecord>,
    now: u64,
    config: &ReputationConfig,
) -> DelegationHygieneMetrics {
    if delegations.is_empty() {
        return DelegationHygieneMetrics {
            score: MetricValue::Unknown,
            delegations_observed: 0,
            scope_reduction_rate: MetricValue::Unknown,
            ttl_reduction_rate: MetricValue::Unknown,
            budget_reduction_rate: MetricValue::Unknown,
        };
    }

    let mut scope_signals = Vec::new();
    let mut ttl_signals = Vec::new();
    let mut budget_signals = Vec::new();

    for child in delegations {
        let Some(parent_id) = child.parent_capability_id.as_deref() else {
            continue;
        };
        let Some(parent) = capability_map.get(parent_id) else {
            continue;
        };

        let weight = decay_weight(now, child.issued_at, config.temporal_decay_half_life_days);
        scope_signals.push((
            bool_to_score(scope_reduced(&parent.scope, &child.scope)),
            weight,
        ));
        ttl_signals.push((bool_to_score(child.expires_at < parent.expires_at), weight));
        budget_signals.push((
            bool_to_score(budget_reduced(&parent.scope, &child.scope)),
            weight,
        ));
    }

    if scope_signals.is_empty() {
        return DelegationHygieneMetrics {
            score: MetricValue::Unknown,
            delegations_observed: 0,
            scope_reduction_rate: MetricValue::Unknown,
            ttl_reduction_rate: MetricValue::Unknown,
            budget_reduction_rate: MetricValue::Unknown,
        };
    }

    let scope_rate = weighted_average(&scope_signals);
    let ttl_rate = weighted_average(&ttl_signals);
    let budget_rate = weighted_average(&budget_signals);

    DelegationHygieneMetrics {
        score: MetricValue::known((scope_rate + ttl_rate + budget_rate) / 3.0),
        delegations_observed: scope_signals.len(),
        scope_reduction_rate: MetricValue::known(scope_rate),
        ttl_reduction_rate: MetricValue::known(ttl_rate),
        budget_reduction_rate: MetricValue::known(budget_rate),
    }
}

fn compute_reliability(
    receipts: &[&PactReceipt],
    now: u64,
    config: &ReputationConfig,
) -> ReliabilityMetrics {
    let mut allow_weight = 0.0;
    let mut cancelled_weight = 0.0;
    let mut incomplete_weight = 0.0;
    let mut observed = 0usize;

    for receipt in receipts {
        let weight = decay_weight(now, receipt.timestamp, config.temporal_decay_half_life_days);
        match receipt.decision {
            Decision::Allow => {
                allow_weight += weight;
                observed += 1;
            }
            Decision::Cancelled { .. } => {
                cancelled_weight += weight;
                observed += 1;
            }
            Decision::Incomplete { .. } => {
                incomplete_weight += weight;
                observed += 1;
            }
            Decision::Deny { .. } => {}
        }
    }

    let total = allow_weight + cancelled_weight + incomplete_weight;
    if total == 0.0 {
        return ReliabilityMetrics {
            score: MetricValue::Unknown,
            completion_rate: MetricValue::Unknown,
            cancellation_rate: MetricValue::Unknown,
            incompletion_rate: MetricValue::Unknown,
            receipts_observed: observed,
        };
    }

    let completion_rate = allow_weight / total;
    let cancellation_rate = cancelled_weight / total;
    let incompletion_rate = incomplete_weight / total;

    ReliabilityMetrics {
        score: MetricValue::known(completion_rate),
        completion_rate: MetricValue::known(completion_rate),
        cancellation_rate: MetricValue::known(cancellation_rate),
        incompletion_rate: MetricValue::known(incompletion_rate),
        receipts_observed: observed,
    }
}

fn compute_incident_correlation(
    subject_key: &str,
    now: u64,
    corpus: &LocalReputationCorpus,
    config: &ReputationConfig,
) -> IncidentCorrelationMetrics {
    let Some(incidents) = corpus.incident_reports.as_ref() else {
        return IncidentCorrelationMetrics {
            score: MetricValue::Unknown,
            incidents_observed: None,
        };
    };

    let _ = subject_key;
    let weighted_incidents = incidents
        .iter()
        .map(|incident| {
            decay_weight(
                now,
                incident.timestamp,
                config.temporal_decay_half_life_days,
            )
        })
        .sum::<f64>();
    let score = 1.0 - config.incident_penalty.max(0.0) * weighted_incidents;

    IncidentCorrelationMetrics {
        score: MetricValue::known(score),
        incidents_observed: Some(incidents.len()),
    }
}

fn contribute_metric(
    metric: Option<f64>,
    weight: f64,
    weighted_sum: &mut f64,
    effective_weight_sum: &mut f64,
) {
    if let Some(value) = metric {
        *weighted_sum += weight * clamp01(value);
        *effective_weight_sum += weight;
    }
}

fn receipt_subject_key(
    receipt: &PactReceipt,
    capability_map: &BTreeMap<&str, &CapabilityLineageRecord>,
) -> Option<String> {
    receipt_attribution(receipt)
        .map(|metadata| metadata.subject_key)
        .or_else(|| {
            capability_map
                .get(receipt.capability_id.as_str())
                .map(|record| record.subject_key.clone())
        })
}

fn receipt_attribution(receipt: &PactReceipt) -> Option<ReceiptAttributionMetadata> {
    let metadata = receipt.metadata.as_ref()?;
    let attribution = metadata.get("attribution")?;
    serde_json::from_value(attribution.clone()).ok()
}

fn weighted_average(values: &[(f64, f64)]) -> f64 {
    let total_weight = values.iter().map(|(_, weight)| weight).sum::<f64>();
    if total_weight == 0.0 {
        0.0
    } else {
        values
            .iter()
            .map(|(value, weight)| value * weight)
            .sum::<f64>()
            / total_weight
    }
}

fn decay_weight(now: u64, timestamp: u64, half_life_days: u32) -> f64 {
    if half_life_days == 0 {
        return 1.0;
    }
    let age_seconds = now.saturating_sub(timestamp) as f64;
    let half_life_seconds = half_life_days as f64 * SECONDS_PER_DAY as f64;
    2f64.powf(-age_seconds / half_life_seconds)
}

fn scope_reduced(parent: &PactScope, child: &PactScope) -> bool {
    if child.grants.len() < parent.grants.len()
        || child.resource_grants.len() < parent.resource_grants.len()
        || child.prompt_grants.len() < parent.prompt_grants.len()
    {
        return true;
    }

    child.grants.iter().any(|child_grant| {
        parent_grant_for(child_grant, parent)
            .map(|parent_grant| grant_scope_reduced(parent_grant, child_grant))
            .unwrap_or(true)
    })
}

fn budget_reduced(parent: &PactScope, child: &PactScope) -> bool {
    child.grants.iter().any(|child_grant| {
        parent_grant_for(child_grant, parent)
            .map(|parent_grant| {
                invocation_limit_reduced(parent_grant, child_grant)
                    || monetary_limit_reduced(parent_grant, child_grant)
            })
            .unwrap_or(true)
    })
}

fn parent_grant_for<'a>(child: &ToolGrant, parent: &'a PactScope) -> Option<&'a ToolGrant> {
    parent
        .grants
        .iter()
        .find(|grant| {
            grant.server_id == child.server_id
                && grant.tool_name == child.tool_name
                && child.is_subset_of(grant)
        })
        .or_else(|| parent.grants.iter().find(|grant| child.is_subset_of(grant)))
}

fn grant_scope_reduced(parent: &ToolGrant, child: &ToolGrant) -> bool {
    child.operations.len() < parent.operations.len()
        || child
            .operations
            .iter()
            .any(|operation| !parent.operations.contains(operation))
        || child.constraints.len() > parent.constraints.len()
        || child
            .constraints
            .iter()
            .any(|constraint| !parent.constraints.contains(constraint))
        || invocation_limit_reduced(parent, child)
        || monetary_limit_reduced(parent, child)
}

fn invocation_limit_reduced(parent: &ToolGrant, child: &ToolGrant) -> bool {
    match (parent.max_invocations, child.max_invocations) {
        (Some(parent_max), Some(child_max)) => child_max < parent_max,
        (None, Some(_)) => true,
        _ => false,
    }
}

fn monetary_limit_reduced(parent: &ToolGrant, child: &ToolGrant) -> bool {
    monetary_cap_reduced(
        parent.max_cost_per_invocation.as_ref(),
        child.max_cost_per_invocation.as_ref(),
    ) || monetary_cap_reduced(
        parent.max_total_cost.as_ref(),
        child.max_total_cost.as_ref(),
    )
}

fn monetary_cap_reduced(
    parent: Option<&pact_core::capability::MonetaryAmount>,
    child: Option<&pact_core::capability::MonetaryAmount>,
) -> bool {
    match (parent, child) {
        (Some(parent_amount), Some(child_amount)) => {
            parent_amount.currency == child_amount.currency
                && child_amount.units < parent_amount.units
        }
        (Some(_), None) => false,
        (None, Some(_)) => true,
        (None, None) => false,
    }
}

fn bool_to_score(value: bool) -> f64 {
    if value {
        1.0
    } else {
        0.0
    }
}

fn clamp01(value: f64) -> f64 {
    value.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pact_core::Constraint;

    #[test]
    fn capability_lineage_record_parses_scope_json() {
        let record = CapabilityLineageRecord::from_scope_json(
            "cap-1",
            "agent-1",
            "issuer-1",
            10,
            20,
            r#"{"grants":[{"server_id":"srv","tool_name":"read","operations":["invoke"],"constraints":[],"max_invocations":10}],"resource_grants":[],"prompt_grants":[]}"#,
            0,
            None,
        )
        .unwrap();

        assert_eq!(record.scope.grants.len(), 1);
        assert_eq!(record.scope.grants[0].tool_name, "read");
    }

    #[test]
    fn metric_value_clamps_inputs() {
        assert_eq!(MetricValue::known(-1.0), MetricValue::Known(0.0));
        assert_eq!(MetricValue::known(2.0), MetricValue::Known(1.0));
    }

    #[test]
    fn scope_reduction_detects_narrower_constraints() {
        let parent = PactScope {
            grants: vec![ToolGrant {
                server_id: "srv".to_string(),
                tool_name: "write".to_string(),
                operations: vec![Operation::Invoke, Operation::Delegate],
                constraints: vec![],
                max_invocations: Some(100),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: vec![],
            prompt_grants: vec![],
        };
        let child = PactScope {
            grants: vec![ToolGrant {
                server_id: "srv".to_string(),
                tool_name: "write".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![Constraint::PathPrefix("/safe".to_string())],
                max_invocations: Some(10),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: vec![],
            prompt_grants: vec![],
        };

        assert!(scope_reduced(&parent, &child));
        assert!(budget_reduced(&parent, &child));
    }
}
