use super::*;
use alloc::collections::BTreeSet;

const EGRESS_VERSION_DOMAIN: &[u8] = b"chio.response-effect-egress-state.v1\0";

pub fn predict_egress_removal(
    current: &EgressRestrictionSnapshot,
    effect_id: &EffectId,
    scheduler_fencing_token: u64,
) -> PortResult<EgressRestrictionSnapshot> {
    validate_egress_restriction_snapshot(current, &current.key)?;
    if scheduler_fencing_token == 0 {
        return Err(PortError::invalid_data());
    }
    let mut contributions = current.contributions.as_slice().to_vec();
    let before = contributions.len();
    contributions.retain(|contribution| &contribution.effect_id != effect_id);
    let generation = if contributions.len() == before {
        current.generation
    } else {
        current
            .generation
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?
    };
    let mut denied = BTreeSet::new();
    for contribution in &contributions {
        denied.extend(contribution.destinations.as_slice().iter().cloned());
    }
    Ok(EgressRestrictionSnapshot {
        key: current.key.clone(),
        generation,
        contributions: EgressRestrictionContributions::new(contributions)
            .map_err(|_| PortError::integrity_failure())?,
        denied_destinations: EgressDeniedDestinations::new(denied.into_iter().collect())
            .map_err(|_| PortError::integrity_failure())?,
        highest_fencing_token: current.highest_fencing_token.max(scheduler_fencing_token),
    })
}

pub fn empty_egress_restriction_snapshot(
    key: EgressRestrictionSessionKey,
) -> PortResult<EgressRestrictionSnapshot> {
    Ok(EgressRestrictionSnapshot {
        key,
        generation: 0,
        contributions: EgressRestrictionContributions::new(Vec::new())
            .map_err(|_| PortError::integrity_failure())?,
        denied_destinations: EgressDeniedDestinations::new(Vec::new())
            .map_err(|_| PortError::integrity_failure())?,
        highest_fencing_token: 0,
    })
}

pub fn validate_egress_restriction_snapshot(
    snapshot: &EgressRestrictionSnapshot,
    expected_key: &EgressRestrictionSessionKey,
) -> PortResult<()> {
    if &snapshot.key != expected_key {
        return Err(PortError::integrity_failure());
    }
    let contributions = snapshot.contributions.as_slice();
    if contributions
        .windows(2)
        .any(|pair| pair[0].effect_id >= pair[1].effect_id)
        || (snapshot.highest_fencing_token == 0 && !contributions.is_empty())
        || snapshot.generation
            < u64::try_from(contributions.len()).map_err(|_| PortError::integrity_failure())?
    {
        return Err(PortError::integrity_failure());
    }
    let mut recomputed = BTreeSet::new();
    for contribution in contributions {
        if contribution.expires_at_unix_ms == 0 {
            return Err(PortError::integrity_failure());
        }
        recomputed.extend(contribution.destinations.as_slice().iter().cloned());
    }
    let recomputed = EgressDeniedDestinations::new(recomputed.into_iter().collect())
        .map_err(|_| PortError::integrity_failure())?;
    if recomputed != snapshot.denied_destinations {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct EgressVersionCommitment<'a> {
    schema_version: u8,
    key: &'a EgressRestrictionSessionKey,
    generation: u64,
    contributions: &'a EgressRestrictionContributions,
    denied_destinations: &'a EgressDeniedDestinations,
}

pub fn egress_snapshot_version_hash(snapshot: &EgressRestrictionSnapshot) -> PortResult<Digest32> {
    issuance_freeze_domain_hash(
        EGRESS_VERSION_DOMAIN,
        &EgressVersionCommitment {
            schema_version: 1,
            key: &snapshot.key,
            generation: snapshot.generation,
            contributions: &snapshot.contributions,
            denied_destinations: &snapshot.denied_destinations,
        },
    )
}

/// Predict the exact destination union using the same rules as live execution.
pub fn predict_egress_apply(
    current: &EgressRestrictionSnapshot,
    contribution: &EgressRestrictionContribution,
    scheduler_fencing_token: u64,
) -> PortResult<EgressRestrictionSnapshot> {
    validate_egress_restriction_snapshot(current, &current.key)?;
    if scheduler_fencing_token == 0 || contribution.expires_at_unix_ms == 0 {
        return Err(PortError::invalid_data());
    }
    let mut next = current.clone();
    let mut contributions = next.contributions.into_vec();
    if let Some(existing) = contributions
        .iter()
        .find(|entry| entry.effect_id == contribution.effect_id)
    {
        if existing != contribution {
            return Err(PortError::conflict());
        }
    } else {
        contributions.push(contribution.clone());
        contributions.sort_by(|left, right| left.effect_id.cmp(&right.effect_id));
        next.generation = next
            .generation
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?;
    }
    let destinations: BTreeSet<_> = contributions
        .iter()
        .flat_map(|entry| entry.destinations.as_slice().iter().cloned())
        .collect();
    next.contributions = EgressRestrictionContributions::new(contributions)
        .map_err(|_| PortError::invalid_data())?;
    next.denied_destinations = EgressDeniedDestinations::new(destinations.into_iter().collect())
        .map_err(|_| PortError::invalid_data())?;
    next.highest_fencing_token = next.highest_fencing_token.max(scheduler_fencing_token);
    validate_egress_restriction_snapshot(&next, &next.key)?;
    Ok(next)
}
