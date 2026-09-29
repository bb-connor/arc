use super::Box;
use super::Vec;
use super::Deserialize;
use super::Serialize;
use super::Digest32;
use super::BoundedVec;
use super::RecordIdSet;
# [cfg (feature = "std")]
use super::issuance_freeze_domain_hash;
use super::EffectRequest;
use super::EffectResult;
use super::EffectResultQuery;
use super::TenantId;
use super::RecordId;
use super::LineageId;
use super::ActionId;
use super::EffectId;
use super::PortError;
use super::PortResult;
use super::BlastRadiusResult;
use super::BlastRadiusFenceAcquisition;
use super::LineageFence;
use super::IssuanceFreezeFenceMaintenanceRequest;
# [cfg (feature = "std")]
use super::response_affected_set_hash;

pub const ISSUANCE_FREEZE_VERSION_DOMAIN: &[u8] =
    b"chio.response-effect-issuance-freeze-state.v1\0";
pub const ISSUANCE_FREEZE_INSTALLED_CONTRIBUTION_DOMAIN: &[u8] =
    b"chio.response-effect-issuance-freeze-contribution.v1\0";
pub type IssuanceFreezeContributions = BoundedVec<IssuanceFreezeContribution, 256>;
pub type IssuanceFreezeMatches = BoundedVec<IssuanceFreezeMatch, 256>;

/// Closed contribution body for a commit-indexed issuance freeze.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceFreezeSpec {
    pub lineage_id: LineageId,
    pub acquisition: BlastRadiusFenceAcquisition,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceFreezeKey {
    pub tenant_id: TenantId,
    pub lineage_id: LineageId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceFreezeContribution {
    pub action_id: ActionId,
    pub effect_id: EffectId,
    pub commit_index: u64,
    pub affected_set_hash: Digest32,
    pub frozen_affected_ids: RecordIdSet,
    pub graph_slice_hash: Digest32,
    /// Rolling external safety lease. Maintenance may extend this beyond the
    /// immutable response-plan expiry while removal is still incomplete.
    pub external_fence: LineageFence,
    pub contribution_hash: Digest32,
    /// Immutable authorization expiry copied from the response plan.
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceFreezeSnapshot {
    pub key: IssuanceFreezeKey,
    pub generation: u64,
    pub contributions: IssuanceFreezeContributions,
    pub highest_scheduler_fencing_token: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceFreezeCommand {
    pub request: EffectRequest,
    pub result: EffectResult,
    pub resulting_snapshot: IssuanceFreezeSnapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceFreezeApplyRequest {
    pub key: IssuanceFreezeKey,
    pub contribution: IssuanceFreezeContribution,
    pub expected_generation: u64,
    pub scheduler_fencing_token: u64,
    pub command: IssuanceFreezeCommand,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceFreezeRemoveRequest {
    pub key: IssuanceFreezeKey,
    pub action_id: ActionId,
    pub effect_id: EffectId,
    pub expected_generation: u64,
    pub scheduler_fencing_token: u64,
    pub command: IssuanceFreezeCommand,
}

/// Exact durable removal command whose external fence release has started but
/// whose local contribution cleanup has not yet committed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceFreezePendingRelease {
    pub request: IssuanceFreezeRemoveRequest,
    pub contribution: IssuanceFreezeContribution,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status", deny_unknown_fields)]
pub enum IssuanceFreezeOperationStatus {
    NotExecuted,
    ReleasePending {
        contribution: Box<IssuanceFreezeContribution>,
    },
    Completed {
        result: EffectResult,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityIssuanceOperation {
    Issue,
    Delegate,
}

impl CapabilityIssuanceOperation {
    pub fn validate_parent(self, parent_capability_id: Option<&RecordId>) -> PortResult<()> {
        if matches!(
            (self, parent_capability_id),
            (Self::Issue, None) | (Self::Delegate, Some(_))
        ) {
            Ok(())
        } else {
            Err(PortError::invalid_data())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceFreezeAdmissionQuery {
    pub tenant_id: TenantId,
    pub lineage_id: LineageId,
    pub operation: CapabilityIssuanceOperation,
    pub parent_capability_id: Option<RecordId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceFreezeMatch {
    pub action_id: ActionId,
    pub effect_id: EffectId,
    pub commit_index: u64,
    pub affected_set_hash: Digest32,
    pub contribution_hash: Digest32,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceFreezeAdmissionDecision {
    pub query: IssuanceFreezeAdmissionQuery,
    pub frozen: bool,
    pub active_matches: IssuanceFreezeMatches,
}

#[cfg(feature = "std")]
pub trait IssuanceFreezeStore: Send + Sync {
    fn ensure_issuance_freezes_ready(&self) -> PortResult<()>;
    fn apply_issuance_freeze(
        &self,
        request: &IssuanceFreezeApplyRequest,
    ) -> PortResult<IssuanceFreezeSnapshot>;
    fn prepare_issuance_freeze_remove(
        &self,
        request: &IssuanceFreezeRemoveRequest,
    ) -> PortResult<IssuanceFreezeContribution>;
    fn complete_issuance_freeze_remove(
        &self,
        request: &IssuanceFreezeRemoveRequest,
    ) -> PortResult<IssuanceFreezeSnapshot>;
    fn load_issuance_freezes(
        &self,
        key: &IssuanceFreezeKey,
    ) -> PortResult<Option<IssuanceFreezeSnapshot>>;
    fn evaluate_issuance_freeze(
        &self,
        query: &IssuanceFreezeAdmissionQuery,
    ) -> PortResult<IssuanceFreezeAdmissionDecision>;
    fn load_issuance_freeze_operation(
        &self,
        query: &EffectResultQuery,
    ) -> PortResult<IssuanceFreezeOperationStatus>;
    fn load_pending_issuance_freeze_release(
        &self,
        _key: &IssuanceFreezeKey,
        _action_id: &ActionId,
        _effect_id: &EffectId,
    ) -> PortResult<Option<IssuanceFreezePendingRelease>> {
        Err(PortError::unavailable())
    }
    fn load_completed_issuance_freeze_release(
        &self,
        _key: &IssuanceFreezeKey,
        _action_id: &ActionId,
        _effect_id: &EffectId,
        _plan_hash: Digest32,
    ) -> PortResult<Option<IssuanceFreezeCommand>> {
        Err(PortError::unavailable())
    }
    fn maintain_issuance_freeze_fence(
        &self,
        _request: &IssuanceFreezeFenceMaintenanceRequest,
    ) -> PortResult<IssuanceFreezeSnapshot> {
        Err(PortError::unavailable())
    }
}

#[cfg(feature = "std")]
mod projection {
use super::*;



#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct IssuanceFreezeVersionCommitment<'a> {
    schema_version: u8,
    key: &'a IssuanceFreezeKey,
    generation: u64,
    contributions: &'a IssuanceFreezeContributions,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct IssuanceFreezeInstalledCommitment<'a> {
    schema_version: u8,
    key: &'a IssuanceFreezeKey,
    action_id: &'a ActionId,
    effect_id: &'a EffectId,
    commit_index: u64,
    affected_set_hash: Digest32,
    frozen_affected_ids: &'a RecordIdSet,
    graph_slice_hash: Digest32,
    contribution_hash: Digest32,
    expires_at_unix_ms: u64,
}

pub fn empty_issuance_freeze_snapshot(
    key: IssuanceFreezeKey,
) -> PortResult<IssuanceFreezeSnapshot> {
    let snapshot = IssuanceFreezeSnapshot {
        key: key.clone(),
        generation: 0,
        contributions: IssuanceFreezeContributions::new(Vec::new())
            .map_err(|_| PortError::integrity_failure())?,
        highest_scheduler_fencing_token: 0,
    };
    validate_issuance_freeze_snapshot(&snapshot, &key)?;
    Ok(snapshot)
}

pub fn validate_issuance_freeze_contribution(
    key: &IssuanceFreezeKey,
    contribution: &IssuanceFreezeContribution,
) -> PortResult<()> {
    let lineage_root =
        RecordId::new(key.lineage_id.as_str()).map_err(|_| PortError::integrity_failure())?;
    if contribution.commit_index == 0
        || contribution.frozen_affected_ids.as_slice().is_empty()
        || contribution
            .frozen_affected_ids
            .as_slice()
            .binary_search(&lineage_root)
            .is_err()
        || contribution.graph_slice_hash == Digest32::new([0_u8; 32])
        || contribution.expires_at_unix_ms == 0
        || response_affected_set_hash(&key.tenant_id, &contribution.frozen_affected_ids)?
            != contribution.affected_set_hash
        || contribution.external_fence.tenant_id != key.tenant_id
        || contribution.external_fence.action_id != contribution.action_id
        || contribution.external_fence.commit_index != contribution.commit_index
        || contribution.external_fence.affected_set_hash != contribution.affected_set_hash
        || contribution.external_fence.fencing_token == 0
        || contribution.external_fence.scheduler_fencing_token == 0
        || contribution.external_fence.expires_at_unix_ms == 0
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

pub fn validate_issuance_freeze_snapshot(
    snapshot: &IssuanceFreezeSnapshot,
    expected_key: &IssuanceFreezeKey,
) -> PortResult<()> {
    if &snapshot.key != expected_key
        || snapshot
            .contributions
            .as_slice()
            .array_windows::<2>()
            .any(|pair| {
                (&pair[0].action_id, &pair[0].effect_id) >= (&pair[1].action_id, &pair[1].effect_id)
            })
    {
        return Err(PortError::integrity_failure());
    }
    for contribution in snapshot.contributions.as_slice() {
        validate_issuance_freeze_contribution(&snapshot.key, contribution)?;
    }
    let contribution_count =
        u64::try_from(snapshot.contributions.len()).map_err(|_| PortError::integrity_failure())?;
    if snapshot.generation < contribution_count
        || (!snapshot.contributions.is_empty() && snapshot.highest_scheduler_fencing_token == 0)
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

pub fn issuance_freeze_version_hash(snapshot: &IssuanceFreezeSnapshot) -> PortResult<Digest32> {
    validate_issuance_freeze_snapshot(snapshot, &snapshot.key)?;
    issuance_freeze_domain_hash(
        ISSUANCE_FREEZE_VERSION_DOMAIN,
        &IssuanceFreezeVersionCommitment {
            schema_version: 1,
            key: &snapshot.key,
            generation: snapshot.generation,
            contributions: &snapshot.contributions,
        },
    )
}

pub fn issuance_freeze_installed_version_hash(
    key: &IssuanceFreezeKey,
    contribution: &IssuanceFreezeContribution,
) -> PortResult<Digest32> {
    validate_issuance_freeze_contribution(key, contribution)?;
    issuance_freeze_domain_hash(
        ISSUANCE_FREEZE_INSTALLED_CONTRIBUTION_DOMAIN,
        &IssuanceFreezeInstalledCommitment {
            schema_version: 1,
            key,
            action_id: &contribution.action_id,
            effect_id: &contribution.effect_id,
            commit_index: contribution.commit_index,
            affected_set_hash: contribution.affected_set_hash,
            frozen_affected_ids: &contribution.frozen_affected_ids,
            graph_slice_hash: contribution.graph_slice_hash,
            contribution_hash: contribution.contribution_hash,
            expires_at_unix_ms: contribution.expires_at_unix_ms,
        },
    )
}

pub fn predict_issuance_freeze_apply(
    current: &IssuanceFreezeSnapshot,
    contribution: &IssuanceFreezeContribution,
    scheduler_fencing_token: u64,
) -> PortResult<IssuanceFreezeSnapshot> {
    validate_issuance_freeze_snapshot(current, &current.key)?;
    validate_issuance_freeze_contribution(&current.key, contribution)?;
    if scheduler_fencing_token == 0 {
        return Err(PortError::invalid_data());
    }
    let mut contributions = current.contributions.clone().into_vec();
    let generation = if let Some(existing) = contributions.iter().find(|entry| {
        entry.action_id == contribution.action_id && entry.effect_id == contribution.effect_id
    }) {
        if existing != contribution {
            return Err(PortError::conflict());
        }
        current.generation
    } else {
        contributions.push(contribution.clone());
        contributions.sort_by(|left, right| {
            (&left.action_id, &left.effect_id).cmp(&(&right.action_id, &right.effect_id))
        });
        current
            .generation
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?
    };
    let snapshot = IssuanceFreezeSnapshot {
        key: current.key.clone(),
        generation,
        contributions: IssuanceFreezeContributions::new(contributions)
            .map_err(|_| PortError::integrity_failure())?,
        highest_scheduler_fencing_token: current
            .highest_scheduler_fencing_token
            .max(scheduler_fencing_token),
    };
    validate_issuance_freeze_snapshot(&snapshot, &current.key)?;
    Ok(snapshot)
}

pub fn predict_issuance_freeze_remove(
    current: &IssuanceFreezeSnapshot,
    action_id: &ActionId,
    effect_id: &EffectId,
    scheduler_fencing_token: u64,
) -> PortResult<IssuanceFreezeSnapshot> {
    validate_issuance_freeze_snapshot(current, &current.key)?;
    if scheduler_fencing_token == 0 {
        return Err(PortError::invalid_data());
    }
    let mut contributions = current.contributions.clone().into_vec();
    let before = contributions.len();
    contributions.retain(|entry| &entry.action_id != action_id || &entry.effect_id != effect_id);
    let removed = contributions.len() != before;
    let generation = if removed {
        current
            .generation
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?
    } else {
        current.generation
    };
    let snapshot = IssuanceFreezeSnapshot {
        key: current.key.clone(),
        generation,
        contributions: IssuanceFreezeContributions::new(contributions)
            .map_err(|_| PortError::integrity_failure())?,
        highest_scheduler_fencing_token: if removed {
            current
                .highest_scheduler_fencing_token
                .max(scheduler_fencing_token)
        } else {
            current.highest_scheduler_fencing_token
        },
    };
    validate_issuance_freeze_snapshot(&snapshot, &current.key)?;
    Ok(snapshot)
}

pub fn validate_issuance_freeze_admission_decision(
    query: &IssuanceFreezeAdmissionQuery,
    decision: &IssuanceFreezeAdmissionDecision,
) -> PortResult<()> {
    query
        .operation
        .validate_parent(query.parent_capability_id.as_ref())?;
    if &decision.query != query
        || decision.frozen == decision.active_matches.is_empty()
        || decision
            .active_matches
            .as_slice()
            .array_windows::<2>()
            .any(|pair| {
                (&pair[0].action_id, &pair[0].effect_id) >= (&pair[1].action_id, &pair[1].effect_id)
            })
        || decision.active_matches.as_slice().iter().any(|entry| {
            entry.commit_index == 0
                || entry.affected_set_hash == Digest32::new([0_u8; 32])
                || entry.contribution_hash == Digest32::new([0_u8; 32])
                || entry.expires_at_unix_ms == 0
        })
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

impl IssuanceFreezeSpec {
    /// Shared closed scope validation for live and simulated issuance effects.
    pub fn validate_for(
        &self,
        key: &IssuanceFreezeKey,
        action_id: &ActionId,
        plan_expires_at_unix_ms: u64,
    ) -> PortResult<()> {
        if self.lineage_id != key.lineage_id
            || self.acquisition.request.tenant_id != key.tenant_id
            || self.acquisition.request.action_id != *action_id
            || self.acquisition.expires_at_unix_ms == 0
            || self.acquisition.expires_at_unix_ms > plan_expires_at_unix_ms
        {
            return Err(PortError::invalid_data());
        }
        let root = RecordId::new(key.lineage_id.as_str()).map_err(PortError::from)?;
        if self.acquisition.request.seed_ids.len() != 1
            || self.acquisition.request.seed_ids.as_slice().first() != Some(&root)
        {
            return Err(PortError::invalid_data());
        }
        let BlastRadiusResult::Exact {
            metadata,
            sorted_affected_ids,
            affected_set_hash,
            graph_slice_hash,
        } = &self.acquisition.approved_result
        else {
            return Err(PortError::invalid_data());
        };
        let bounds = &self.acquisition.request.query_bounds;
        if bounds.max_depth == 0
            || bounds.max_nodes == 0
            || bounds.max_edges == 0
            || metadata.query_bounds != *bounds
            || metadata.source_lineage_version == 0
            || metadata.commit_index == 0
            || metadata.commit_index != metadata.authoritative_commit_index
            || metadata
                .completeness_watermark
                .is_none_or(|watermark| watermark < metadata.commit_index)
            || sorted_affected_ids.as_slice().binary_search(&root).is_err()
            || response_affected_set_hash(&key.tenant_id, sorted_affected_ids)?
                != *affected_set_hash
            || *graph_slice_hash == Digest32::new([0_u8; 32])
        {
            return Err(PortError::invalid_data());
        }
        Ok(())
    }
}

}

#[cfg(feature = "std")]
pub use projection::{empty_issuance_freeze_snapshot, validate_issuance_freeze_contribution, validate_issuance_freeze_snapshot, issuance_freeze_version_hash, issuance_freeze_installed_version_hash, predict_issuance_freeze_apply, predict_issuance_freeze_remove, validate_issuance_freeze_admission_decision};
