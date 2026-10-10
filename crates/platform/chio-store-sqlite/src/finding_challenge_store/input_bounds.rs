// Input bounds, required-field checks, and error mapping.

/// Apply the appeal-final transition and retain its exact authorization in a
/// caller-owned transaction. The status store uses this boundary so the
/// signed authorization, sticky retraction outbox, and liability edge cannot
/// be committed independently.
pub(crate) fn begin_finalizing_under_sanction_tx(
    transaction: &Transaction<'_>,
    liability_key: &str,
    expected_state: FindingLiabilityState,
    sanction_case_id: &str,
    authorization: &FindingFinalizingAuthorizationInput<'_>,
    now: u64,
) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
    require_hex64(liability_key, "liability_key")?;
    require_identifier(sanction_case_id, "sanction_case_id")?;
    require_finalizing_authorization(authorization)?;
    if authorization.liability_key != liability_key || authorization.recorded_at != now {
        return Err(invariant(
            "finalizing authorization does not bind the transition",
        ));
    }
    require_trusted_time(now, "now")?;
    require_transition_source(
        expected_state,
        FindingLiabilityState::PendingAppeal,
        FindingLiabilityState::Finalizing,
    )?;
    let head = resolve_case_head_tx(transaction, liability_key)?.ok_or_else(|| {
        FindingChallengeStoreError::Conflict("liability carries no live governance case".to_owned())
    })?;
    if head.case_kind != FindingGovernanceCaseKind::Sanction || head.case_id != sanction_case_id {
        return Err(FindingChallengeStoreError::Conflict(
            "the named sanction is not the live governance case".to_owned(),
        ));
    }
    let retained = transaction
        .query_row(
            r#"
            SELECT authorization_json, authorization_sha256, recorded_at
            FROM finding_finalizing_authorizations
            WHERE liability_key = ?1
            "#,
            [liability_key],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    if let Some((bytes, digest, recorded_at)) = &retained {
        if bytes != authorization.authorization_json
            || digest != authorization.authorization_sha256
            || stored_u64(*recorded_at, "finalizing authorization recorded_at")?
                != authorization.recorded_at
        {
            return Err(FindingChallengeStoreError::Conflict(
                "finalizing authorization is already bound to different bytes".to_owned(),
            ));
        }
    }
    let (outcome, _) = apply_liability_transition_tx(
        transaction,
        liability_key,
        FindingLiabilityState::PendingAppeal,
        FindingLiabilityState::Finalizing,
        Some(true),
        now,
    )?;
    if outcome == FindingChallengeWriteOutcome::ExistingSame && retained.is_none() {
        return Err(invariant(
            "finalizing liability has no retained authorization",
        ));
    }
    if outcome == FindingChallengeWriteOutcome::ExistingSame {
        return Ok(outcome);
    }
    let inserted = transaction
        .execute(
            r#"
            INSERT INTO finding_finalizing_authorizations (
                liability_key, authorization_json,
                authorization_sha256, recorded_at
            ) VALUES (?1, ?2, ?3, ?4)
            "#,
            params![
                liability_key,
                authorization.authorization_json,
                authorization.authorization_sha256,
                sqlite_i64(authorization.recorded_at, "recorded_at")?,
            ],
        )
        .map_err(sqlite_error)?;
    if inserted != 1 {
        return Err(invariant(
            "finalizing authorization insert did not affect one row",
        ));
    }
    Ok(outcome)
}
