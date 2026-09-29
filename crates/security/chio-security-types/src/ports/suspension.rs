#[cfg(feature = "std")]
use super::sort_json_object_keys;
use super::{
    ActionId, BoundedVec, Deserialize, Digest32, EffectId, EffectRequest, EffectResult, RecordId,
    RecordIdSet, Serialize, TenantId,
};
#[cfg(feature = "std")]
use super::{
    EffectExecutionStatus, EffectResultQuery, PortError, PortResult, Vec,
    RESPONSE_AFFECTED_SET_DOMAIN,
};

pub const CAPABILITY_SET_SUSPENSION_VERSION_DOMAIN: &[u8] =
    b"chio.response-effect-capability-set-suspension-state.v1\0";
pub const CAPABILITY_SET_SUSPENSION_INSTALLED_CONTRIBUTION_DOMAIN: &[u8] =
    b"chio.response-effect-capability-set-suspension-contribution.v1\0";
pub type CapabilitySetSuspensionContributions =
    BoundedVec<CapabilitySetSuspensionContribution, 256>;
pub type CapabilitySetSuspensionMatches = BoundedVec<CapabilitySetSuspensionMatch, 256>;

/// Closed contribution body for an exact capability-set suspension.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySetSuspensionSpec {
    pub affected_ids: RecordIdSet,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySetSuspensionKey {
    pub tenant_id: TenantId,
    pub affected_set_hash: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySetSuspensionContribution {
    pub action_id: ActionId,
    pub effect_id: EffectId,
    pub affected_ids: RecordIdSet,
    pub contribution_hash: Digest32,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySetSuspensionSnapshot {
    pub key: CapabilitySetSuspensionKey,
    pub generation: u64,
    pub contributions: CapabilitySetSuspensionContributions,
    pub highest_fencing_token: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySetSuspensionCommand {
    pub request: EffectRequest,
    pub result: EffectResult,
    pub resulting_snapshot: CapabilitySetSuspensionSnapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySetSuspensionApplyRequest {
    pub key: CapabilitySetSuspensionKey,
    pub contribution: CapabilitySetSuspensionContribution,
    pub expected_generation: u64,
    pub scheduler_fencing_token: u64,
    pub command: CapabilitySetSuspensionCommand,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySetSuspensionRemoveRequest {
    pub key: CapabilitySetSuspensionKey,
    pub action_id: ActionId,
    pub effect_id: EffectId,
    pub expected_generation: u64,
    pub scheduler_fencing_token: u64,
    pub command: CapabilitySetSuspensionCommand,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySuspensionQuery {
    pub tenant_id: TenantId,
    pub capability_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySetSuspensionMatch {
    pub affected_set_hash: Digest32,
    pub action_id: ActionId,
    pub effect_id: EffectId,
    pub contribution_hash: Digest32,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySuspensionDecision {
    pub tenant_id: TenantId,
    pub capability_id: RecordId,
    pub denied: bool,
    pub active_matches: CapabilitySetSuspensionMatches,
}

#[cfg(feature = "std")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ResponseAffectedSetCommitment<'a> {
    tenant_id: &'a str,
    affected_ids: &'a [RecordId],
}

#[cfg(feature = "std")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CapabilitySetSuspensionVersionCommitment<'a> {
    schema_version: u8,
    key: &'a CapabilitySetSuspensionKey,
    generation: u64,
    contributions: &'a CapabilitySetSuspensionContributions,
}

#[cfg(feature = "std")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CapabilitySetSuspensionInstalledCommitment<'a> {
    schema_version: u8,
    key: &'a CapabilitySetSuspensionKey,
    contribution: &'a CapabilitySetSuspensionContribution,
}

#[cfg(feature = "std")]
pub fn response_affected_set_hash(
    tenant_id: &TenantId,
    affected_ids: &RecordIdSet,
) -> PortResult<Digest32> {
    if affected_ids.as_slice().is_empty() {
        return Err(PortError::invalid_data());
    }
    capability_set_suspension_domain_hash(
        RESPONSE_AFFECTED_SET_DOMAIN,
        &ResponseAffectedSetCommitment {
            tenant_id: tenant_id.as_str(),
            affected_ids: affected_ids.as_slice(),
        },
    )
}

#[cfg(feature = "std")]
pub fn empty_capability_set_suspension_snapshot(
    key: CapabilitySetSuspensionKey,
) -> PortResult<CapabilitySetSuspensionSnapshot> {
    let snapshot = CapabilitySetSuspensionSnapshot {
        key: key.clone(),
        generation: 0,
        contributions: CapabilitySetSuspensionContributions::new(Vec::new())
            .map_err(|_| PortError::integrity_failure())?,
        highest_fencing_token: 0,
    };
    validate_capability_set_suspension_snapshot(&snapshot, &key)?;
    Ok(snapshot)
}

#[cfg(feature = "std")]
pub fn validate_capability_set_suspension_snapshot(
    snapshot: &CapabilitySetSuspensionSnapshot,
    expected_key: &CapabilitySetSuspensionKey,
) -> PortResult<()> {
    if &snapshot.key != expected_key {
        return Err(PortError::integrity_failure());
    }
    let contributions = snapshot.contributions.as_slice();
    if contributions.array_windows::<2>().any(|pair| {
        (&pair[0].action_id, &pair[0].effect_id) >= (&pair[1].action_id, &pair[1].effect_id)
    }) {
        return Err(PortError::integrity_failure());
    }
    for contribution in contributions {
        if contribution.expires_at_unix_ms == 0
            || response_affected_set_hash(&snapshot.key.tenant_id, &contribution.affected_ids)?
                != snapshot.key.affected_set_hash
        {
            return Err(PortError::integrity_failure());
        }
    }
    let contribution_count =
        u64::try_from(contributions.len()).map_err(|_| PortError::integrity_failure())?;
    if snapshot.generation < contribution_count
        || (!contributions.is_empty() && snapshot.highest_fencing_token == 0)
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

#[cfg(feature = "std")]
pub fn capability_set_suspension_version_hash(
    snapshot: &CapabilitySetSuspensionSnapshot,
) -> PortResult<Digest32> {
    validate_capability_set_suspension_snapshot(snapshot, &snapshot.key)?;
    capability_set_suspension_domain_hash(
        CAPABILITY_SET_SUSPENSION_VERSION_DOMAIN,
        &CapabilitySetSuspensionVersionCommitment {
            schema_version: 1,
            key: &snapshot.key,
            generation: snapshot.generation,
            contributions: &snapshot.contributions,
        },
    )
}

#[cfg(feature = "std")]
pub fn capability_set_suspension_installed_version_hash(
    key: &CapabilitySetSuspensionKey,
    contribution: &CapabilitySetSuspensionContribution,
) -> PortResult<Digest32> {
    if response_affected_set_hash(&key.tenant_id, &contribution.affected_ids)?
        != key.affected_set_hash
    {
        return Err(PortError::invalid_data());
    }
    capability_set_suspension_domain_hash(
        CAPABILITY_SET_SUSPENSION_INSTALLED_CONTRIBUTION_DOMAIN,
        &CapabilitySetSuspensionInstalledCommitment {
            schema_version: 1,
            key,
            contribution,
        },
    )
}

#[cfg(feature = "std")]
pub fn predict_capability_set_suspension_apply(
    current: &CapabilitySetSuspensionSnapshot,
    contribution: &CapabilitySetSuspensionContribution,
    scheduler_fencing_token: u64,
) -> PortResult<CapabilitySetSuspensionSnapshot> {
    validate_capability_set_suspension_snapshot(current, &current.key)?;
    if scheduler_fencing_token == 0
        || response_affected_set_hash(&current.key.tenant_id, &contribution.affected_ids)?
            != current.key.affected_set_hash
    {
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
    let snapshot = CapabilitySetSuspensionSnapshot {
        key: current.key.clone(),
        generation,
        contributions: CapabilitySetSuspensionContributions::new(contributions)
            .map_err(|_| PortError::integrity_failure())?,
        highest_fencing_token: current.highest_fencing_token.max(scheduler_fencing_token),
    };
    validate_capability_set_suspension_snapshot(&snapshot, &current.key)?;
    Ok(snapshot)
}

#[cfg(feature = "std")]
pub fn predict_capability_set_suspension_remove(
    current: &CapabilitySetSuspensionSnapshot,
    action_id: &ActionId,
    effect_id: &EffectId,
    scheduler_fencing_token: u64,
) -> PortResult<CapabilitySetSuspensionSnapshot> {
    validate_capability_set_suspension_snapshot(current, &current.key)?;
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
    let snapshot = CapabilitySetSuspensionSnapshot {
        key: current.key.clone(),
        generation,
        contributions: CapabilitySetSuspensionContributions::new(contributions)
            .map_err(|_| PortError::integrity_failure())?,
        highest_fencing_token: if removed {
            current.highest_fencing_token.max(scheduler_fencing_token)
        } else {
            current.highest_fencing_token
        },
    };
    validate_capability_set_suspension_snapshot(&snapshot, &current.key)?;
    Ok(snapshot)
}

#[cfg(feature = "std")]
pub fn validate_capability_suspension_decision(
    query: &CapabilitySuspensionQuery,
    decision: &CapabilitySuspensionDecision,
) -> PortResult<()> {
    if decision.tenant_id != query.tenant_id
        || decision.capability_id != query.capability_id
        || decision.denied == decision.active_matches.is_empty()
        || decision
            .active_matches
            .as_slice()
            .array_windows::<2>()
            .any(|pair| {
                (
                    pair[0].action_id.as_str(),
                    pair[0].effect_id.as_str(),
                    pair[0].affected_set_hash,
                ) >= (
                    pair[1].action_id.as_str(),
                    pair[1].effect_id.as_str(),
                    pair[1].affected_set_hash,
                )
            })
        || decision
            .active_matches
            .as_slice()
            .iter()
            .any(|entry| entry.expires_at_unix_ms == 0)
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

#[cfg(feature = "std")]
fn capability_set_suspension_domain_hash(
    domain: &[u8],
    commitment: &impl Serialize,
) -> PortResult<Digest32> {
    use sha2::{Digest as _, Sha256};

    let mut value = serde_json::to_value(commitment).map_err(|_| PortError::integrity_failure())?;
    sort_json_object_keys(&mut value);
    let canonical = serde_json::to_vec(&value).map_err(|_| PortError::integrity_failure())?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    Ok(Digest32::new(hasher.finalize().into()))
}

#[cfg(feature = "std")]
pub trait CapabilitySetSuspensionStore: Send + Sync {
    fn ensure_capability_set_suspensions_ready(&self) -> PortResult<()>;
    fn apply_capability_set_suspension(
        &self,
        request: &CapabilitySetSuspensionApplyRequest,
    ) -> PortResult<CapabilitySetSuspensionSnapshot>;
    fn remove_capability_set_suspension(
        &self,
        request: &CapabilitySetSuspensionRemoveRequest,
    ) -> PortResult<CapabilitySetSuspensionSnapshot>;
    fn load_capability_set_suspensions(
        &self,
        key: &CapabilitySetSuspensionKey,
    ) -> PortResult<Option<CapabilitySetSuspensionSnapshot>>;
    fn evaluate_capability_suspension(
        &self,
        query: &CapabilitySuspensionQuery,
    ) -> PortResult<CapabilitySuspensionDecision>;
    fn load_capability_set_suspension_result(
        &self,
        query: &EffectResultQuery,
    ) -> PortResult<EffectExecutionStatus>;
}
