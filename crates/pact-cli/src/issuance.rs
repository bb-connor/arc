use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use pact_core::capability::{
    Constraint, Operation, PactScope, PromptGrant, ResourceGrant, ToolGrant,
};
use pact_core::crypto::PublicKey;
use pact_kernel::{BudgetStore, CapabilityAuthority, KernelError};
use pact_reputation::{
    compute_local_scorecard, BudgetUsageRecord as ReputationBudgetUsageRecord,
    CapabilityLineageRecord, LocalReputationCorpus, LocalReputationScorecard, ReputationConfig,
};
use pact_store_sqlite::{SqliteBudgetStore, SqliteReceiptStore};
use serde::{Deserialize, Serialize};

use crate::policy::{ReputationIssuancePolicy, ReputationTierPolicy, TierScopeCeiling};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReputationScoringSource {
    Default,
    IssuancePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProbationaryStatus {
    pub below_receipt_target: bool,
    pub below_day_target: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LocalReputationTierView {
    pub name: String,
    pub score_range: [f64; 2],
    pub max_scope: TierScopeCeiling,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LocalReputationInspection {
    pub subject_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    pub scoring_source: ReputationScoringSource,
    pub scoring: ReputationConfig,
    pub probationary_receipt_count: u64,
    pub probationary_min_days: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probationary_score_ceiling: Option<f64>,
    pub probationary: bool,
    pub probationary_status: ProbationaryStatus,
    pub effective_score: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_tier: Option<LocalReputationTierView>,
    pub scorecard: LocalReputationScorecard,
}

pub fn wrap_capability_authority(
    inner: Box<dyn CapabilityAuthority>,
    issuance_policy: Option<ReputationIssuancePolicy>,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
) -> Box<dyn CapabilityAuthority> {
    if issuance_policy.is_none() && receipt_db_path.is_none() {
        return inner;
    }

    Box::new(PolicyBackedCapabilityAuthority {
        inner,
        issuance_policy,
        receipt_db_path: receipt_db_path.map(Path::to_path_buf),
        budget_db_path: budget_db_path.map(Path::to_path_buf),
    })
}

struct PolicyBackedCapabilityAuthority {
    inner: Box<dyn CapabilityAuthority>,
    issuance_policy: Option<ReputationIssuancePolicy>,
    receipt_db_path: Option<PathBuf>,
    budget_db_path: Option<PathBuf>,
}

impl CapabilityAuthority for PolicyBackedCapabilityAuthority {
    fn authority_public_key(&self) -> PublicKey {
        self.inner.authority_public_key()
    }

    fn trusted_public_keys(&self) -> Vec<PublicKey> {
        self.inner.trusted_public_keys()
    }

    fn issue_capability(
        &self,
        subject: &PublicKey,
        scope: PactScope,
        ttl_seconds: u64,
    ) -> Result<pact_core::capability::CapabilityToken, KernelError> {
        if let Some(policy) = &self.issuance_policy {
            enforce_reputation_policy(
                subject,
                &scope,
                ttl_seconds,
                policy,
                self.receipt_db_path.as_deref(),
                self.budget_db_path.as_deref(),
            )?;
        }

        let capability = self.inner.issue_capability(subject, scope, ttl_seconds)?;

        if let Some(path) = self.receipt_db_path.as_deref() {
            let mut store = SqliteReceiptStore::open(path)
                .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?;
            store
                .record_capability_snapshot(&capability, None)
                .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?;
        }

        Ok(capability)
    }
}

fn enforce_reputation_policy(
    subject: &PublicKey,
    scope: &PactScope,
    ttl_seconds: u64,
    policy: &ReputationIssuancePolicy,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
) -> Result<(), KernelError> {
    let subject_key = subject.to_hex();
    let inspection = inspect_local_reputation(
        &subject_key,
        receipt_db_path,
        budget_db_path,
        None,
        None,
        Some(policy),
    )?;
    let tier = inspection.resolved_tier.ok_or_else(|| {
        KernelError::CapabilityIssuanceFailed(
            "reputation issuance policy did not resolve a matching tier".to_string(),
        )
    })?;

    let tier_policy = ReputationTierPolicy {
        name: tier.name,
        score_range: tier.score_range,
        max_scope: tier.max_scope,
    };
    enforce_tier_scope(scope, ttl_seconds, &tier_policy)
}

pub(crate) fn inspect_local_reputation(
    subject_key: &str,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    since: Option<u64>,
    until: Option<u64>,
    issuance_policy: Option<&ReputationIssuancePolicy>,
) -> Result<LocalReputationInspection, KernelError> {
    let corpus =
        build_local_reputation_corpus(subject_key, receipt_db_path, budget_db_path, since, until)?;
    let (scoring_source, scoring, probationary_receipt_count, probationary_min_days, ceiling) =
        scoring_context(issuance_policy);
    let now = unix_now();
    let scorecard = compute_local_scorecard(subject_key, now, &corpus, &scoring);
    let probationary_status = ProbationaryStatus {
        below_receipt_target: scorecard.history_depth.receipt_count
            < probationary_receipt_count as usize,
        below_day_target: scorecard.history_depth.span_days < probationary_min_days,
    };
    let probationary =
        probationary_status.below_receipt_target || probationary_status.below_day_target;
    let effective_score = scorecard.composite_score.as_option().unwrap_or(0.0);
    let effective_score = ceiling
        .filter(|_| probationary)
        .map_or(effective_score, |limit| effective_score.min(limit));
    let resolved_tier = issuance_policy
        .and_then(|policy| resolve_tier(policy, effective_score))
        .map(|tier| LocalReputationTierView {
            name: tier.name.clone(),
            score_range: tier.score_range,
            max_scope: tier.max_scope.clone(),
        });

    Ok(LocalReputationInspection {
        subject_key: subject_key.to_string(),
        since,
        until,
        scoring_source,
        scoring,
        probationary_receipt_count,
        probationary_min_days,
        probationary_score_ceiling: ceiling,
        probationary,
        probationary_status,
        effective_score,
        resolved_tier,
        scorecard,
    })
}

pub fn build_local_reputation_corpus(
    subject_key: &str,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    since: Option<u64>,
    until: Option<u64>,
) -> Result<LocalReputationCorpus, KernelError> {
    let mut receipts = Vec::new();
    let mut capabilities = BTreeMap::new();

    if let Some(path) = receipt_db_path {
        let store = SqliteReceiptStore::open(path)
            .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?;
        receipts = store
            .list_tool_receipts_for_subject(subject_key)
            .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?
            .into_iter()
            .filter(|receipt| {
                since.is_none_or(|since| receipt.body().timestamp >= since)
                    && until.is_none_or(|until| receipt.body().timestamp <= until)
            })
            .collect();

        for snapshot in store
            .list_capability_snapshots(Some(subject_key), None)
            .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?
            .into_iter()
            .chain(
                store
                    .list_capability_snapshots(None, Some(subject_key))
                    .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?,
            )
        {
            capabilities
                .entry(snapshot.capability_id.clone())
                .or_insert(
                    CapabilityLineageRecord::from_scope_json(
                        snapshot.capability_id,
                        snapshot.subject_key,
                        snapshot.issuer_key,
                        snapshot.issued_at,
                        snapshot.expires_at,
                        &snapshot.grants_json,
                        snapshot.delegation_depth,
                        snapshot.parent_capability_id,
                    )
                    .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?,
                );
        }
    }

    let mut budget_usage = Vec::new();
    if let Some(path) = budget_db_path {
        let store = SqliteBudgetStore::open(path)
            .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?;
        for capability in capabilities.values() {
            for grant_index in 0..capability.scope.grants.len() {
                if let Some(record) = store
                    .get_usage(&capability.capability_id, grant_index)
                    .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?
                {
                    budget_usage.push(ReputationBudgetUsageRecord {
                        capability_id: record.capability_id,
                        grant_index: record.grant_index,
                        invocation_count: record.invocation_count,
                        updated_at: record.updated_at,
                        total_cost_charged: record.total_cost_charged,
                    });
                }
            }
        }
    }

    Ok(LocalReputationCorpus {
        receipts,
        capabilities: capabilities.into_values().collect(),
        budget_usage,
        incident_reports: None,
    })
}

fn resolve_tier(
    policy: &ReputationIssuancePolicy,
    effective_score: f64,
) -> Option<&ReputationTierPolicy> {
    policy
        .tiers
        .iter()
        .rfind(|tier| score_in_range(effective_score, tier.score_range))
        .or_else(|| policy.tiers.first())
}

fn score_in_range(score: f64, score_range: [f64; 2]) -> bool {
    score >= score_range[0] && score <= score_range[1]
}

fn enforce_tier_scope(
    scope: &PactScope,
    ttl_seconds: u64,
    tier: &ReputationTierPolicy,
) -> Result<(), KernelError> {
    if ttl_seconds > tier.max_scope.ttl_seconds {
        return Err(KernelError::CapabilityIssuanceDenied(format!(
            "requested ttl_seconds {ttl_seconds} exceeds reputation tier '{}' ceiling {}",
            tier.name, tier.max_scope.ttl_seconds
        )));
    }

    for grant in &scope.grants {
        enforce_tool_grant(grant, tier)?;
    }
    for grant in &scope.resource_grants {
        enforce_resource_grant(grant, tier)?;
    }
    for grant in &scope.prompt_grants {
        enforce_prompt_grant(grant, tier)?;
    }

    Ok(())
}

fn enforce_tool_grant(grant: &ToolGrant, tier: &ReputationTierPolicy) -> Result<(), KernelError> {
    if tier.max_scope.constraints_required && grant.constraints.is_empty() {
        return Err(KernelError::CapabilityIssuanceDenied(format!(
            "reputation tier '{}' requires constrained tool grants",
            tier.name
        )));
    }

    if tier.max_scope.max_delegation_depth == Some(0)
        && grant.operations.contains(&Operation::Delegate)
    {
        return Err(KernelError::CapabilityIssuanceDenied(format!(
            "reputation tier '{}' does not allow delegated capability issuance",
            tier.name
        )));
    }

    let ceiling = ToolGrant {
        server_id: grant.server_id.clone(),
        tool_name: grant.tool_name.clone(),
        operations: tier.max_scope.operations.clone(),
        constraints: if tier.max_scope.constraints_required {
            required_constraints(grant)
        } else {
            Vec::new()
        },
        max_invocations: tier.max_scope.max_invocations,
        max_cost_per_invocation: tier.max_scope.max_cost_per_invocation.clone(),
        max_total_cost: tier.max_scope.max_total_cost.clone(),
        dpop_required: None,
    };
    if grant.is_subset_of(&ceiling) {
        Ok(())
    } else {
        Err(KernelError::CapabilityIssuanceDenied(format!(
            "requested tool grant '{}'/'{}' exceeds reputation tier '{}' scope ceiling",
            grant.server_id, grant.tool_name, tier.name
        )))
    }
}

fn enforce_resource_grant(
    grant: &ResourceGrant,
    tier: &ReputationTierPolicy,
) -> Result<(), KernelError> {
    let ceiling = ResourceGrant {
        uri_pattern: grant.uri_pattern.clone(),
        operations: tier.max_scope.operations.clone(),
    };
    if grant.is_subset_of(&ceiling) {
        Ok(())
    } else {
        Err(KernelError::CapabilityIssuanceDenied(format!(
            "requested resource grant '{}' exceeds reputation tier '{}' scope ceiling",
            grant.uri_pattern, tier.name
        )))
    }
}

fn enforce_prompt_grant(
    grant: &PromptGrant,
    tier: &ReputationTierPolicy,
) -> Result<(), KernelError> {
    let ceiling = PromptGrant {
        prompt_name: grant.prompt_name.clone(),
        operations: tier.max_scope.operations.clone(),
    };
    if grant.is_subset_of(&ceiling) {
        Ok(())
    } else {
        Err(KernelError::CapabilityIssuanceDenied(format!(
            "requested prompt grant '{}' exceeds reputation tier '{}' scope ceiling",
            grant.prompt_name, tier.name
        )))
    }
}

fn required_constraints(grant: &ToolGrant) -> Vec<Constraint> {
    grant.constraints.clone()
}

fn scoring_context(
    issuance_policy: Option<&ReputationIssuancePolicy>,
) -> (
    ReputationScoringSource,
    ReputationConfig,
    u64,
    u64,
    Option<f64>,
) {
    if let Some(policy) = issuance_policy {
        (
            ReputationScoringSource::IssuancePolicy,
            policy.scoring.clone(),
            policy.probationary_receipt_count,
            policy.probationary_min_days,
            Some(policy.probationary_score_ceiling),
        )
    } else {
        let scoring = ReputationConfig::default();
        (
            ReputationScoringSource::Default,
            scoring.clone(),
            scoring.history_receipt_target,
            scoring.history_day_target,
            None,
        )
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;

    use pact_core::capability::{CapabilityToken, MonetaryAmount, Operation, ToolGrant};
    use pact_core::crypto::Keypair;
    use pact_core::receipt::{
        Decision, PactReceipt, PactReceiptBody, ReceiptAttributionMetadata, ToolCallAction,
    };
    use pact_kernel::ReceiptStore;
    use pact_store_sqlite::SqliteReceiptStore;

    use crate::policy::TierScopeCeiling;

    fn unique_path(prefix: &str, extension: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}{extension}"))
    }

    fn test_policy() -> ReputationIssuancePolicy {
        ReputationIssuancePolicy {
            scoring: pact_reputation::ReputationConfig {
                history_receipt_target: 10,
                history_day_target: 10,
                ..Default::default()
            },
            probationary_receipt_count: 10,
            probationary_min_days: 10,
            probationary_score_ceiling: 0.60,
            tiers: vec![
                ReputationTierPolicy {
                    name: "probationary".to_string(),
                    score_range: [0.0, 0.50],
                    max_scope: TierScopeCeiling {
                        operations: vec![Operation::Read, Operation::Get],
                        max_invocations: Some(50),
                        max_cost_per_invocation: Some(MonetaryAmount {
                            units: 100,
                            currency: "USD".to_string(),
                        }),
                        max_total_cost: Some(MonetaryAmount {
                            units: 1_000,
                            currency: "USD".to_string(),
                        }),
                        max_delegation_depth: Some(0),
                        ttl_seconds: 60,
                        constraints_required: true,
                    },
                },
                ReputationTierPolicy {
                    name: "trusted".to_string(),
                    score_range: [0.50, 1.0],
                    max_scope: TierScopeCeiling {
                        operations: vec![
                            Operation::Read,
                            Operation::Get,
                            Operation::Invoke,
                            Operation::ReadResult,
                            Operation::Delegate,
                        ],
                        max_invocations: Some(500),
                        max_cost_per_invocation: Some(MonetaryAmount {
                            units: 1_000,
                            currency: "USD".to_string(),
                        }),
                        max_total_cost: Some(MonetaryAmount {
                            units: 10_000,
                            currency: "USD".to_string(),
                        }),
                        max_delegation_depth: Some(3),
                        ttl_seconds: 300,
                        constraints_required: false,
                    },
                },
            ],
        }
    }

    fn make_receipt(
        id: &str,
        capability_id: &str,
        subject_key: &str,
        issuer_key: &str,
        timestamp: u64,
    ) -> PactReceipt {
        let kernel_kp = Keypair::generate();
        PactReceipt::sign(
            PactReceiptBody {
                id: id.to_string(),
                timestamp,
                capability_id: capability_id.to_string(),
                tool_server: "filesystem".to_string(),
                tool_name: "read_file".to_string(),
                action: ToolCallAction::from_parameters(serde_json::json!({
                    "path": "/workspace/safe/data.txt"
                }))
                .expect("action"),
                decision: Decision::Allow,
                content_hash: format!("content-{id}"),
                policy_hash: "policy-hash".to_string(),
                evidence: Vec::new(),
                metadata: Some(serde_json::json!({
                    "attribution": ReceiptAttributionMetadata {
                        subject_key: subject_key.to_string(),
                        issuer_key: issuer_key.to_string(),
                        delegation_depth: 0,
                        grant_index: Some(0),
                    }
                })),
                kernel_key: kernel_kp.public_key(),
            },
            &kernel_kp,
        )
        .expect("sign receipt")
    }

    fn make_subject_capability(
        capability_id: &str,
        subject_kp: &Keypair,
        issuer_kp: &Keypair,
        issued_at: u64,
        max_invocations: Option<u32>,
    ) -> CapabilityToken {
        let body = pact_core::capability::CapabilityTokenBody {
            id: capability_id.to_string(),
            issuer: issuer_kp.public_key(),
            subject: subject_kp.public_key(),
            scope: PactScope {
                grants: vec![ToolGrant {
                    server_id: "filesystem".to_string(),
                    tool_name: "read_file".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![Constraint::PathPrefix("/workspace/safe".to_string())],
                    max_invocations,
                    max_cost_per_invocation: Some(MonetaryAmount {
                        units: 250,
                        currency: "USD".to_string(),
                    }),
                    max_total_cost: Some(MonetaryAmount {
                        units: 2_500,
                        currency: "USD".to_string(),
                    }),
                    dpop_required: None,
                }],
                resource_grants: Vec::new(),
                prompt_grants: Vec::new(),
            },
            issued_at,
            expires_at: issued_at + 3_600,
            delegation_chain: Vec::new(),
        };
        CapabilityToken::sign(body, issuer_kp).expect("sign capability")
    }

    #[test]
    fn probationary_subject_requires_constrained_read_scope_and_persists_snapshot() {
        let receipt_db_path = unique_path("issuance-policy-receipts", ".sqlite3");
        let authority = wrap_capability_authority(
            Box::new(pact_kernel::LocalCapabilityAuthority::new(
                Keypair::generate(),
            )),
            Some(test_policy()),
            Some(&receipt_db_path),
            None,
        );
        let subject_kp = Keypair::generate();
        let scope = PactScope {
            grants: vec![ToolGrant {
                server_id: "filesystem".to_string(),
                tool_name: "read_file".to_string(),
                operations: vec![Operation::Read],
                constraints: vec![Constraint::PathPrefix("/workspace/safe".to_string())],
                max_invocations: Some(10),
                max_cost_per_invocation: Some(MonetaryAmount {
                    units: 50,
                    currency: "USD".to_string(),
                }),
                max_total_cost: Some(MonetaryAmount {
                    units: 500,
                    currency: "USD".to_string(),
                }),
                dpop_required: None,
            }],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        };

        let capability = authority
            .issue_capability(&subject_kp.public_key(), scope, 30)
            .expect("probationary read capability should issue");

        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        let stored = store
            .get_lineage(&capability.id)
            .expect("lineage query")
            .expect("snapshot present");
        assert_eq!(stored.subject_key, subject_kp.public_key().to_hex());

        let _ = fs::remove_file(receipt_db_path);
    }

    #[test]
    fn probationary_subject_denied_broad_issue_request() {
        let receipt_db_path = unique_path("issuance-policy-deny", ".sqlite3");
        let authority = wrap_capability_authority(
            Box::new(pact_kernel::LocalCapabilityAuthority::new(
                Keypair::generate(),
            )),
            Some(test_policy()),
            Some(&receipt_db_path),
            None,
        );
        let subject_kp = Keypair::generate();
        let scope = PactScope {
            grants: vec![ToolGrant {
                server_id: "filesystem".to_string(),
                tool_name: "read_file".to_string(),
                operations: vec![Operation::Invoke, Operation::Delegate],
                constraints: Vec::new(),
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        };

        let error = authority
            .issue_capability(&subject_kp.public_key(), scope, 300)
            .expect_err("broad probationary issuance should be denied");
        assert!(
            matches!(error, KernelError::CapabilityIssuanceDenied(_)),
            "expected denial, got {error:?}"
        );

        let _ = fs::remove_file(receipt_db_path);
    }

    #[test]
    fn strong_local_history_allows_trusted_invoke_scope() {
        let receipt_db_path = unique_path("issuance-policy-history", ".sqlite3");
        let mut receipt_store = SqliteReceiptStore::open(&receipt_db_path).expect("receipt store");
        let subject_kp = Keypair::generate();
        let issuer_kp = Keypair::generate();
        let subject_hex = subject_kp.public_key().to_hex();
        let issuer_hex = issuer_kp.public_key().to_hex();
        let now = unix_now();
        let subject_capability = make_subject_capability(
            "cap-history-001",
            &subject_kp,
            &issuer_kp,
            now - 20 * 86_400,
            Some(200),
        );
        receipt_store
            .record_capability_snapshot(&subject_capability, None)
            .expect("record subject capability");
        for day in 0..12 {
            let receipt = make_receipt(
                &format!("rcpt-{day}"),
                &subject_capability.id,
                &subject_hex,
                &issuer_hex,
                now - (11 - day) * 86_400,
            );
            receipt_store
                .append_pact_receipt(&receipt)
                .expect("append receipt");
        }
        drop(receipt_store);

        let authority = wrap_capability_authority(
            Box::new(pact_kernel::LocalCapabilityAuthority::new(
                Keypair::generate(),
            )),
            Some(test_policy()),
            Some(&receipt_db_path),
            None,
        );
        let requested_scope = PactScope {
            grants: vec![ToolGrant {
                server_id: "filesystem".to_string(),
                tool_name: "read_file".to_string(),
                operations: vec![Operation::Invoke, Operation::Delegate],
                constraints: Vec::new(),
                max_invocations: Some(250),
                max_cost_per_invocation: Some(MonetaryAmount {
                    units: 500,
                    currency: "USD".to_string(),
                }),
                max_total_cost: Some(MonetaryAmount {
                    units: 5_000,
                    currency: "USD".to_string(),
                }),
                dpop_required: None,
            }],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        };

        let capability = authority
            .issue_capability(&subject_kp.public_key(), requested_scope, 300)
            .expect("trusted issuance should succeed");
        assert_eq!(capability.subject, subject_kp.public_key());

        let _ = fs::remove_file(receipt_db_path);
    }
}
