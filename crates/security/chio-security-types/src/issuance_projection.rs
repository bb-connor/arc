//! Shared pure issuance composition and scope validation.

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
