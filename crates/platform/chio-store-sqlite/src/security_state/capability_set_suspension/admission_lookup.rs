//! Complete tenant discovery with a finite, fail-closed admission work budget.
use super::*;
use crate::receipt_store::support::{decoded_json_text_bytes, SqlWorkBudget};
use chio_security_types::ports::PortErrorKind;
use rusqlite::types::ValueRef;

/// Bound on sets that currently hold at least one contribution.
const MAX_SETS: u64 = 1024;
const MAX_CONTRIBUTIONS: u64 = 4096;
const MAX_MEMBERS: u64 = 65_536;
const MAX_BODY_BYTES: u64 = 1024 * 1024;
const MAX_RAW_BYTES: u64 = 16 * 1024 * 1024;
const MAX_DECODED_BYTES: u64 = 8 * 1024 * 1024;
const MAX_SQL_STEPS: u64 = 10_000_000;
const MAX_IDENTIFIER_BYTES: u64 = 1024;

#[derive(Debug, thiserror::Error)]
enum LookupExhaustion {
    #[error("historical suspension set-key limit")]
    Sets,
    #[error("suspension contribution limit")]
    Contributions,
    #[error("suspension member limit")]
    Members,
    #[error("suspension canonical body byte limit")]
    RawBytes,
    #[error("suspension decoded JSON text byte limit")]
    DecodedBytes,
    #[error("suspension member identifier byte limit")]
    MemberBytes,
    #[error("suspension SQL work limit")]
    SqlWork,
}

fn exhausted(reason: LookupExhaustion) -> PortError {
    PortError::with_source(
        PortErrorKind::Unavailable,
        "store.suspension_lookup_budget_exhausted",
        reason,
    )
}

#[derive(Default)]
struct LookupBudget {
    sets: u64,
    contributions: u64,
    members: u64,
    raw_bytes: u64,
    decoded_bytes: u64,
    member_bytes: u64,
}

fn charge(current: &mut u64, amount: u64, limit: u64, reason: LookupExhaustion) -> PortResult<()> {
    *current = current
        .checked_add(amount)
        .filter(|next| *next <= limit)
        .ok_or_else(|| exhausted(reason))?;
    Ok(())
}

fn bytes(row: &rusqlite::Row<'_>, column: usize) -> PortResult<u64> {
    from_i64(row.get(column).map_err(sqlite_error)?)
}

fn identifier_bytes(row: &rusqlite::Row<'_>, column: usize) -> PortResult<u64> {
    let actual = match row.get_ref(column).map_err(sqlite_error)? {
        ValueRef::Text(value) => crate::integer::count(value.len()),
        _ => return Err(PortError::integrity_failure()),
    };
    if actual > MAX_IDENTIFIER_BYTES {
        return Err(PortError::integrity_failure());
    }
    // Existing ActionId/EffectId/RecordId validation still enforces the stricter
    // semantic identifier limit when the pinned verifier creates owned values.
    Ok(actual)
}

fn preflight(
    connection: &Connection,
    key: &CapabilitySetSuspensionKey,
    budget: &mut LookupBudget,
) -> PortResult<()> {
    let remaining = MAX_CONTRIBUTIONS
        .checked_sub(budget.contributions)
        .ok_or_else(|| exhausted(LookupExhaustion::Contributions))?;
    let mut statement = connection.prepare_cached(
        "SELECT octet_length(action_id), octet_length(effect_id), octet_length(affected_ids_body),
            octet_length(contribution_hash), CASE WHEN octet_length(affected_ids_body) <= ?3 THEN affected_ids_body END,
            CASE WHEN octet_length(action_id) <= ?5 THEN action_id END,
            CASE WHEN octet_length(effect_id) <= ?5 THEN effect_id END
         FROM security_capability_set_suspension_effects
         WHERE tenant_id = ?1 AND affected_set_hash = ?2 ORDER BY action_id, effect_id LIMIT ?4"
    ).map_err(sqlite_error)?;
    let mut rows = statement
        .query(params![
            key.tenant_id.as_str(),
            key.affected_set_hash.as_bytes().as_slice(),
            to_i64(MAX_BODY_BYTES)?,
            to_i64(
                remaining
                    .checked_add(1)
                    .ok_or_else(|| exhausted(LookupExhaustion::Contributions))?
            )?,
            to_i64(MAX_IDENTIFIER_BYTES * 2)?
        ])
        .map_err(sqlite_error)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        charge(
            &mut budget.contributions,
            1,
            MAX_CONTRIBUTIONS,
            LookupExhaustion::Contributions,
        )?;
        if bytes(row, 0)? > MAX_IDENTIFIER_BYTES * 2
            || bytes(row, 1)? > MAX_IDENTIFIER_BYTES * 2
            || bytes(row, 3)? != 32
        {
            return Err(PortError::integrity_failure());
        }
        identifier_bytes(row, 5)?;
        identifier_bytes(row, 6)?;
        let raw_bytes = bytes(row, 2)?;
        if raw_bytes > MAX_BODY_BYTES {
            return Err(exhausted(LookupExhaustion::RawBytes));
        }
        charge(
            &mut budget.raw_bytes,
            raw_bytes,
            MAX_RAW_BYTES,
            LookupExhaustion::RawBytes,
        )?;
        let raw = match row.get_ref(4).map_err(sqlite_error)? {
            ValueRef::Blob(raw) => {
                std::str::from_utf8(raw).map_err(|_| PortError::integrity_failure())?
            }
            _ => return Err(PortError::integrity_failure()),
        };
        let decoded = decoded_json_text_bytes(raw).map_err(|error| {
            PortError::with_source(
                PortErrorKind::IntegrityFailure,
                "store.integrity_failure",
                error,
            )
        })?;
        charge(
            &mut budget.decoded_bytes,
            decoded,
            MAX_DECODED_BYTES,
            LookupExhaustion::DecodedBytes,
        )?;
    }
    drop(rows);
    drop(statement);
    let remaining = MAX_MEMBERS
        .checked_sub(budget.members)
        .ok_or_else(|| exhausted(LookupExhaustion::Members))?;
    let mut statement = connection
        .prepare_cached(
            "SELECT octet_length(capability_id), CASE WHEN octet_length(capability_id) <= ?4 THEN capability_id END FROM security_capability_set_suspension_members
         WHERE tenant_id = ?1 AND affected_set_hash = ?2
         ORDER BY action_id, effect_id, capability_id LIMIT ?3",
        )
        .map_err(sqlite_error)?;
    let mut rows = statement
        .query(params![
            key.tenant_id.as_str(),
            key.affected_set_hash.as_bytes().as_slice(),
            to_i64(
                remaining
                    .checked_add(1)
                    .ok_or_else(|| exhausted(LookupExhaustion::Members))?
            )?,
            to_i64(MAX_IDENTIFIER_BYTES * 2)?
        ])
        .map_err(sqlite_error)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        charge(
            &mut budget.members,
            1,
            MAX_MEMBERS,
            LookupExhaustion::Members,
        )?;
        if bytes(row, 0)? > MAX_IDENTIFIER_BYTES * 2 {
            return Err(PortError::integrity_failure());
        }
        let size = identifier_bytes(row, 1)?;
        charge(
            &mut budget.member_bytes,
            size,
            MAX_RAW_BYTES,
            LookupExhaustion::MemberBytes,
        )?;
    }
    // The same transaction pins these size/count checks and the existing full
    // canonical/hash/member verifier. No index absence is used as an Allow.
    Ok(())
}

pub(super) fn evaluate(
    store: &SqliteSecurityStateStore,
    query: &CapabilitySuspensionQuery,
) -> PortResult<CapabilitySuspensionDecision> {
    let mut connection = store.connection()?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(sqlite_error)?;
    let progress =
        SqlWorkBudget::new_for(&transaction, MAX_SQL_STEPS, "capability suspension lookup")
            .map_err(|error| {
                PortError::with_source(PortErrorKind::Unavailable, "store.unavailable", error)
            })?;
    let result = evaluate_in_snapshot(&transaction, query);
    let result = if progress.exhausted() {
        Err(exhausted(LookupExhaustion::SqlWork))
    } else {
        result
    };
    drop(progress);
    let decision = result?;
    transaction.commit().map_err(sqlite_error)?;
    Ok(decision)
}

fn evaluate_in_snapshot(
    connection: &Connection,
    query: &CapabilitySuspensionQuery,
) -> PortResult<CapabilitySuspensionDecision> {
    // Discovery is driven by the contribution rows themselves: only sets that
    // still hold a contribution count against the set budget, and every such
    // set (including one with no state row) is fully verified by load_snapshot.
    // State rows of sets with no remaining contribution keep their generation
    // and fencing token for stale-apply rejection but are never enumerated.
    let mut statement = connection.prepare_cached(
        "SELECT octet_length(affected_set_hash), CASE WHEN octet_length(affected_set_hash) = 32 THEN affected_set_hash END
         FROM security_capability_set_suspension_effects WHERE tenant_id = ?1
         GROUP BY affected_set_hash ORDER BY affected_set_hash LIMIT ?2"
    ).map_err(sqlite_error)?;
    let mut rows = statement
        .query(params![query.tenant_id.as_str(), to_i64(MAX_SETS + 1)?])
        .map_err(sqlite_error)?;
    let mut budget = LookupBudget::default();
    let mut matches = Vec::new();
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        charge(&mut budget.sets, 1, MAX_SETS, LookupExhaustion::Sets)?;
        if bytes(row, 0)? != 32 {
            return Err(PortError::integrity_failure());
        }
        let key = CapabilitySetSuspensionKey {
            tenant_id: query.tenant_id.clone(),
            affected_set_hash: decode_digest(row.get(1).map_err(sqlite_error)?)?,
        };
        preflight(connection, &key, &mut budget)?;
        let snapshot = load_snapshot(connection, &key)?;
        for contribution in snapshot.contributions.as_slice() {
            if contribution
                .affected_ids
                .as_slice()
                .binary_search(&query.capability_id)
                .is_ok()
            {
                matches.push(CapabilitySetSuspensionMatch {
                    affected_set_hash: key.affected_set_hash,
                    action_id: contribution.action_id.clone(),
                    effect_id: contribution.effect_id.clone(),
                    contribution_hash: contribution.contribution_hash,
                    expires_at_unix_ms: contribution.expires_at_unix_ms,
                });
            }
        }
    }
    matches.sort_by(|left, right| {
        (&left.action_id, &left.effect_id, left.affected_set_hash).cmp(&(
            &right.action_id,
            &right.effect_id,
            right.affected_set_hash,
        ))
    });
    let active_matches =
        CapabilitySetSuspensionMatches::new(matches).map_err(|_| PortError::integrity_failure())?;
    let decision = CapabilitySuspensionDecision {
        tenant_id: query.tenant_id.clone(),
        capability_id: query.capability_id.clone(),
        denied: !active_matches.is_empty(),
        active_matches,
    };
    validate_capability_suspension_decision(query, &decision)?;
    Ok(decision)
}
