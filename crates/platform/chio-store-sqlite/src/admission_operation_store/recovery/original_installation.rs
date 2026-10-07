//! Exact historical installation selected by an original protected commit.
use super::*;

/// Read within the caller's authenticated, fenced authority transaction.
/// The caller first validates its complete original record and authorization.
pub(super) fn for_record(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    original_key: &str,
) -> Result<Option<RecoveryDeploymentV1>, AdmissionOperationStoreError> {
    let scope_hash = scope_key(scope)?;
    let original = raw_checked(tx, original_key)?
        .ok_or_else(|| invariant("original authority record is absent"))?;
    if original.scope != scope_hash || original.kind != "command" || original.version == 0 {
        return Err(invariant("original authority record scope changed"));
    }
    let first_original = historical_record_commit(tx, original_key, 1)?;
    let deployment_key = format!("deployment:{scope_hash}");
    let selected: Option<(i64, i64)> = tx
        .query_row(
            "SELECT commit_sequence,projection_sequence FROM authority_global_commits
             WHERE projection_kind='recovery' AND projection_key=?1 AND commit_sequence<?2
             ORDER BY commit_sequence DESC LIMIT 1",
            params![
                &deployment_key,
                i64::try_from(first_original)
                    .map_err(|_| invariant("original authority commit exhausted"))?
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((installed_commit, installed_version)) = selected else {
        return Ok(None);
    };
    let installed_commit = stored_u64(installed_commit, "original installation commit")?;
    let installed_version = stored_u64(installed_version, "original installation version")?;
    if historical_record_commit(tx, &deployment_key, installed_version)? != installed_commit
        || installed_commit >= first_original
    {
        return Err(invariant("original installation ordering changed"));
    }

    // Each candidate must match the exact earlier installation's authenticated
    // record digest. Archive time or a current assignment cannot select it.
    // Stream scoped keys, including retained references to lost physical rows.
    let history_pattern = format!("deployment-history:{scope_hash}:*");
    let mut statement = tx
        .prepare(
            "SELECT ?1 AS record_key
             UNION SELECT record_key FROM admission_operation_recovery_records
                 WHERE record_key GLOB ?2
             UNION SELECT record_key FROM admission_operation_recovery_events
                 WHERE record_key GLOB ?2
             UNION SELECT projection_key FROM authority_global_commits
                 WHERE projection_kind='recovery' AND projection_key GLOB ?2
             ORDER BY record_key",
        )
        .map_err(sqlite_error)?;
    let keys = statement
        .query_map(params![&deployment_key, &history_pattern], |row| {
            row.get::<_, String>(0)
        })
        .map_err(sqlite_error)?;
    for candidate_key in keys {
        let candidate_key = candidate_key.map_err(sqlite_error)?;
        let row = raw_checked(tx, &candidate_key)?
            .ok_or_else(|| invariant("retained original installation disappeared"))?;
        let profile: RecoveryDeploymentV1 = decode(&row.payload)?;
        if row.kind != "deployment" || row.scope != scope_hash || profile.scope != *scope {
            return Err(invariant("retained original installation scope changed"));
        }
        if candidate_key != deployment_key {
            let digest =
                DeploymentDigest::from_bytes(hash(RecoveryDigestDomain::Deployment, &profile)?);
            if row.version != 1 || candidate_key != key(scope, digest)? {
                return Err(invariant("retained original installation identity changed"));
            }
        }
        if !matches_historical_deployment(
            tx,
            &deployment_key,
            &scope_hash,
            installed_version,
            &profile,
        )? {
            continue;
        }
        if profile.authority_scope
            != recovery_authority_scope_digest(&profile)
                .map_err(|_| invariant("original authority digest refused"))?
        {
            return Err(invariant("original authority scope changed"));
        }
        return Ok(Some(profile));
    }
    Ok(None)
}
