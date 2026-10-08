//! Input validation and transactional writes for finding status feeds,
//! epochs, intents, leaves and proofs.

use super::*;

pub(super) fn validate_epoch_input(
    input: &VerifiedFindingStatusEpochInput<'_>,
) -> Result<(), FindingStatusStoreError> {
    require_identifier(input.feed_id, "feed_id")?;
    require_identifier(input.operator_id, "operator_id")?;
    require_identifier_with_bound(input.operator_key, 4_096, "operator_key")?;
    require_fixed_nonce(input.key_domain_nonce)?;
    require_positive(input.map_epoch, "map_epoch")?;
    require_hex64(input.epoch_id, "epoch_id")?;
    require_hex64(input.root_hash, "root_hash")?;
    require_hex64(
        input.operator_authorization_sha256,
        "operator_authorization_sha256",
    )?;
    require_bytes(
        input.signed_epoch_bytes,
        MAX_FINDING_STATUS_EPOCH_BYTES,
        "signed_epoch_bytes",
    )?;
    require_positive(input.generated_at, "generated_at")?;
    if input.valid_until <= input.generated_at {
        return Err(invariant("epoch valid_until must follow generated_at"));
    }
    if input.recorded_at < input.generated_at {
        return Err(invariant("epoch recorded_at predates generated_at"));
    }
    sqlite_i64(input.operator_key_epoch, "operator_key_epoch")?;
    sqlite_i64(input.valid_until, "valid_until")?;
    sqlite_i64(input.recorded_at, "recorded_at")?;
    Ok(())
}

pub(super) fn validate_intent_input(
    input: &FindingRetractionIntentInput<'_>,
) -> Result<(), FindingStatusStoreError> {
    require_hex64(input.intent_id, "intent_id")?;
    require_identifier(input.feed_id, "feed_id")?;
    require_identifier(input.operator_id, "operator_id")?;
    require_hex64(input.finding_id, "finding_id")?;
    require_bytes(
        input.intent_bytes,
        MAX_FINDING_RETRACTION_EVIDENCE_BYTES,
        "intent_bytes",
    )?;
    require_positive(input.issued_at, "issued_at")?;
    if input.inclusion_deadline <= input.issued_at {
        return Err(invariant("intent inclusion_deadline must follow issued_at"));
    }
    if input.created_at < input.issued_at {
        return Err(invariant("intent created_at predates issued_at"));
    }
    sqlite_i64(input.inclusion_deadline, "inclusion_deadline")?;
    sqlite_i64(input.created_at, "created_at")?;
    Ok(())
}

pub(super) fn validate_intent_commit_liveness(
    input: &FindingRetractionIntentInput<'_>,
    liveness: FindingRetractionIntentCommitLiveness,
) -> Result<(), FindingStatusStoreError> {
    require_positive(liveness.valid_from, "intent authority valid_from")?;
    if liveness.valid_until <= liveness.valid_from {
        return Err(invariant(
            "intent authority valid_until must follow valid_from",
        ));
    }
    if input.issued_at < liveness.valid_from || input.inclusion_deadline >= liveness.valid_until {
        return Err(FindingStatusStoreError::Conflict(
            "retraction intent is not covered through its inclusion deadline".to_owned(),
        ));
    }
    sqlite_i64(liveness.valid_until, "intent authority valid_until")?;
    Ok(())
}

pub(super) fn validate_leaf_input(
    input: &VerifiedFindingStatusLeafInput<'_>,
) -> Result<(), FindingStatusStoreError> {
    require_hex64(input.finding_id, "finding_id")?;
    require_bytes(
        input.status_value_bytes,
        MAX_FINDING_STATUS_VALUE_BYTES,
        "status_value_bytes",
    )?;
    require_hex64(input.retraction_intent_sha256, "retraction_intent_sha256")?;
    if let Some(intent_id) = input.local_intent_id {
        require_hex64(intent_id, "local_intent_id")?;
    }
    Ok(())
}

pub(super) fn validate_proof_input(
    input: &VerifiedFindingStatusProofInput<'_>,
) -> Result<(), FindingStatusStoreError> {
    require_identifier(input.feed_id, "feed_id")?;
    require_identifier(input.operator_id, "operator_id")?;
    require_fixed_nonce(input.key_domain_nonce)?;
    require_positive(input.map_epoch, "map_epoch")?;
    require_hex64(input.epoch_id, "epoch_id")?;
    require_hex64(input.root_hash, "root_hash")?;
    require_hex64(input.finding_id, "finding_id")?;
    require_bytes(
        input.proof_bytes,
        MAX_FINDING_STATUS_PROOF_BYTES,
        "proof_bytes",
    )?;
    require_positive(input.checked_at, "checked_at")?;
    if input.valid_until <= input.checked_at {
        return Err(invariant("proof valid_until must follow checked_at"));
    }
    if input.recorded_at < input.checked_at {
        return Err(invariant("proof recorded_at predates checked_at"));
    }
    match input.kind {
        FindingStatusProofKind::Inclusion => {
            let value = input
                .status_value_bytes
                .ok_or_else(|| invariant("inclusion proof is missing its exact status value"))?;
            require_bytes(value, MAX_FINDING_STATUS_VALUE_BYTES, "status_value_bytes")?;
            require_hex64(
                input.retraction_intent_sha256.ok_or_else(|| {
                    invariant("inclusion proof is missing its retraction intent digest")
                })?,
                "retraction_intent_sha256",
            )?;
        }
        FindingStatusProofKind::NonInclusion => {
            if input.status_value_bytes.is_some() || input.retraction_intent_sha256.is_some() {
                return Err(invariant(
                    "non-inclusion proof carries inclusion-only fields",
                ));
            }
        }
    }
    sqlite_i64(input.valid_until, "valid_until")?;
    sqlite_i64(input.recorded_at, "recorded_at")?;
    Ok(())
}

pub(super) fn verify_proof_epoch_binding(
    proof: &VerifiedFindingStatusProofInput<'_>,
    epoch: &VerifiedFindingStatusEpochInput<'_>,
) -> Result<(), FindingStatusStoreError> {
    if proof.feed_id != epoch.feed_id
        || proof.operator_id != epoch.operator_id
        || proof.key_domain_nonce != epoch.key_domain_nonce
        || proof.map_epoch != epoch.map_epoch
        || proof.epoch_id != epoch.epoch_id
        || proof.root_hash != epoch.root_hash
    {
        return Err(invariant("proof does not bind the supplied signed epoch"));
    }
    if proof.valid_until > epoch.valid_until {
        return Err(invariant("proof freshness exceeds its signed epoch"));
    }
    Ok(())
}

pub(super) fn verify_proof_floor_binding(
    proof: &VerifiedFindingStatusProofInput<'_>,
    floor: &FindingStatusFeedFloor,
) -> Result<(), FindingStatusStoreError> {
    if proof.feed_id != floor.feed_id
        || proof.operator_id != floor.operator_id
        || proof.key_domain_nonce != floor.key_domain_nonce
    {
        return Err(invariant("proof does not bind the durable feed identity"));
    }
    if proof.map_epoch < floor.map_epoch {
        return Err(FindingStatusStoreError::Rollback {
            feed_id: proof.feed_id.to_owned(),
            current: floor.map_epoch,
            proposed: proof.map_epoch,
        });
    }
    if proof.map_epoch != floor.map_epoch
        || proof.epoch_id != floor.epoch_id
        || proof.root_hash != floor.root_hash
    {
        return Err(FindingStatusStoreError::Equivocation {
            feed_id: proof.feed_id.to_owned(),
            map_epoch: proof.map_epoch,
        });
    }
    Ok(())
}

pub(super) fn require_unique_leaf_inputs(
    leaves: &[VerifiedFindingStatusLeafInput<'_>],
) -> Result<(), FindingStatusStoreError> {
    let mut ids = leaves
        .iter()
        .map(|leaf| leaf.finding_id)
        .collect::<Vec<_>>();
    ids.sort_unstable();
    if ids.array_windows::<2>().any(|pair| pair[0] == pair[1]) {
        return Err(invariant("epoch advance contains duplicate leaf updates"));
    }
    Ok(())
}

pub(super) fn require_unique_proof_inputs(
    proofs: &[VerifiedFindingStatusProofInput<'_>],
) -> Result<(), FindingStatusStoreError> {
    let mut ids = proofs
        .iter()
        .map(|proof| proof.finding_id)
        .collect::<Vec<_>>();
    ids.sort_unstable();
    if ids.array_windows::<2>().any(|pair| pair[0] == pair[1]) {
        return Err(invariant("epoch advance contains duplicate proof inputs"));
    }
    Ok(())
}

pub(super) fn require_leaf_proofs(
    leaves: &[VerifiedFindingStatusLeafInput<'_>],
    proofs: &[VerifiedFindingStatusProofInput<'_>],
) -> Result<(), FindingStatusStoreError> {
    for leaf in leaves {
        let matching = proofs.iter().find(|proof| {
            proof.finding_id == leaf.finding_id && proof.kind == FindingStatusProofKind::Inclusion
        });
        let Some(proof) = matching else {
            return Err(invariant(
                "every epoch leaf update requires its exact inclusion proof",
            ));
        };
        if proof.status_value_bytes != Some(leaf.status_value_bytes)
            || proof.retraction_intent_sha256 != Some(leaf.retraction_intent_sha256)
        {
            return Err(invariant(
                "leaf update does not match its portable inclusion proof",
            ));
        }
    }
    Ok(())
}
pub(super) fn persist_epoch_record_tx(
    transaction: &Transaction<'_>,
    epoch: &VerifiedFindingStatusEpochInput<'_>,
) -> Result<FindingStatusWriteOutcome, FindingStatusStoreError> {
    let signed_epoch_sha256 = sha256_hex(epoch.signed_epoch_bytes);
    match load_epoch_tx(transaction, epoch.feed_id, epoch.map_epoch)? {
        Some(existing) if epoch_record_matches_input(&existing, epoch, &signed_epoch_sha256) => {
            Ok(FindingStatusWriteOutcome::ExactReplay)
        }
        Some(_) => Err(FindingStatusStoreError::Equivocation {
            feed_id: epoch.feed_id.to_owned(),
            map_epoch: epoch.map_epoch,
        }),
        None => {
            transaction
                .execute(
                    r#"
                    INSERT INTO finding_status_epochs (
                        feed_id, operator_id, key_domain_nonce, map_epoch, epoch_id,
                        root_hash, signed_epoch_sha256, signed_epoch_bytes,
                        operator_key, operator_key_epoch,
                        operator_authorization_sha256, generated_at, valid_until,
                        recorded_at
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                              ?11, ?12, ?13, ?14)
                    "#,
                    params![
                        epoch.feed_id,
                        epoch.operator_id,
                        sqlite_i64(epoch.key_domain_nonce, "key_domain_nonce")?,
                        sqlite_i64(epoch.map_epoch, "map_epoch")?,
                        epoch.epoch_id,
                        epoch.root_hash,
                        signed_epoch_sha256,
                        epoch.signed_epoch_bytes,
                        epoch.operator_key,
                        sqlite_i64(epoch.operator_key_epoch, "operator_key_epoch")?,
                        epoch.operator_authorization_sha256,
                        sqlite_i64(epoch.generated_at, "generated_at")?,
                        sqlite_i64(epoch.valid_until, "valid_until")?,
                        sqlite_i64(epoch.recorded_at, "recorded_at")?,
                    ],
                )
                .map_err(sqlite_error)?;
            Ok(FindingStatusWriteOutcome::Inserted)
        }
    }
}

pub(super) fn persist_epoch_tx(
    transaction: &Transaction<'_>,
    epoch: &VerifiedFindingStatusEpochInput<'_>,
    prior_floor: Option<&FindingStatusFeedFloor>,
    advance_floor: bool,
) -> Result<FindingStatusWriteOutcome, FindingStatusStoreError> {
    let signed_epoch_sha256 = sha256_hex(epoch.signed_epoch_bytes);
    if prior_floor.is_none() {
        let pre_epoch_high_water = transaction
            .query_row(
                r#"
                SELECT MAX(observed_at) FROM (
                    SELECT registered_at AS observed_at
                    FROM finding_status_feeds
                    WHERE feed_id = ?1
                    UNION ALL
                    SELECT created_at AS observed_at
                    FROM finding_retraction_intents
                    WHERE feed_id = ?1
                )
                "#,
                [epoch.feed_id],
                |row| row.get::<_, Option<i64>>(0),
            )
            .map_err(sqlite_error)?
            .map(|value| stored_u64(value, "pre-epoch trusted time"))
            .transpose()?
            .unwrap_or(0);
        if epoch.recorded_at < pre_epoch_high_water {
            return Err(FindingStatusStoreError::ClockRollback {
                feed_id: epoch.feed_id.to_owned(),
                high_water: pre_epoch_high_water,
                observed: epoch.recorded_at,
            });
        }
    }
    if let Some(floor) = prior_floor {
        if floor.operator_id != epoch.operator_id
            || floor.key_domain_nonce != epoch.key_domain_nonce
        {
            return Err(invariant(
                "signed epoch changed the durable feed/operator identity",
            ));
        }
        if epoch.map_epoch < floor.map_epoch {
            return Err(FindingStatusStoreError::Rollback {
                feed_id: epoch.feed_id.to_owned(),
                current: floor.map_epoch,
                proposed: epoch.map_epoch,
            });
        }
        if epoch.map_epoch == floor.map_epoch {
            let existing = load_epoch_tx(transaction, epoch.feed_id, epoch.map_epoch)?
                .ok_or_else(|| invariant("status floor points to a missing epoch"))?;
            if epoch_record_matches_input(&existing, epoch, &signed_epoch_sha256) {
                return Ok(FindingStatusWriteOutcome::ExactReplay);
            }
            return Err(FindingStatusStoreError::Equivocation {
                feed_id: epoch.feed_id.to_owned(),
                map_epoch: epoch.map_epoch,
            });
        }
        reject_epoch_clock_rollback(epoch, floor)?;
        if epoch.operator_key_epoch < floor.operator_key_epoch {
            return Err(invariant("operator key epoch regressed across feed epochs"));
        }
        if epoch.operator_key_epoch == floor.operator_key_epoch
            && epoch.operator_key != floor.operator_key
        {
            return Err(invariant("operator key changed without key-epoch rotation"));
        }
        if epoch.operator_key_epoch == floor.operator_key_epoch
            && epoch.operator_authorization_sha256 != floor.operator_authorization_sha256
        {
            return Err(invariant(
                "operator authorization changed without key-epoch rotation",
            ));
        }
    } else if feed_has_epochs_tx(transaction, epoch.feed_id)? {
        return Err(FindingStatusStoreError::MissingFloor {
            feed_id: epoch.feed_id.to_owned(),
        });
    }

    let epoch_outcome = persist_epoch_record_tx(transaction, epoch)?;

    if !advance_floor {
        return Ok(epoch_outcome);
    }

    if prior_floor.is_some() {
        transaction
            .execute(
                r#"
                UPDATE finding_status_feed_floors
                SET map_epoch = ?2, epoch_id = ?3, root_hash = ?4,
                    signed_epoch_sha256 = ?5, operator_key = ?6,
                    operator_key_epoch = ?7,
                    operator_authorization_sha256 = ?8, advanced_at = ?9
                WHERE feed_id = ?1
                "#,
                params![
                    epoch.feed_id,
                    sqlite_i64(epoch.map_epoch, "map_epoch")?,
                    epoch.epoch_id,
                    epoch.root_hash,
                    signed_epoch_sha256,
                    epoch.operator_key,
                    sqlite_i64(epoch.operator_key_epoch, "operator_key_epoch")?,
                    epoch.operator_authorization_sha256,
                    sqlite_i64(epoch.recorded_at, "recorded_at")?,
                ],
            )
            .map_err(sqlite_error)?;
    } else {
        transaction
            .execute(
                r#"
                INSERT INTO finding_status_feed_floors (
                    feed_id, operator_id, key_domain_nonce, map_epoch, epoch_id,
                    root_hash, signed_epoch_sha256, operator_key,
                    operator_key_epoch, operator_authorization_sha256,
                    advanced_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                "#,
                params![
                    epoch.feed_id,
                    epoch.operator_id,
                    sqlite_i64(epoch.key_domain_nonce, "key_domain_nonce")?,
                    sqlite_i64(epoch.map_epoch, "map_epoch")?,
                    epoch.epoch_id,
                    epoch.root_hash,
                    signed_epoch_sha256,
                    epoch.operator_key,
                    sqlite_i64(epoch.operator_key_epoch, "operator_key_epoch")?,
                    epoch.operator_authorization_sha256,
                    sqlite_i64(epoch.recorded_at, "recorded_at")?,
                ],
            )
            .map_err(sqlite_error)?;
    }
    Ok(FindingStatusWriteOutcome::Inserted)
}

pub(super) fn persist_leaf_tx(
    transaction: &Transaction<'_>,
    epoch: &VerifiedFindingStatusEpochInput<'_>,
    leaf: &VerifiedFindingStatusLeafInput<'_>,
) -> Result<FindingStatusWriteOutcome, FindingStatusStoreError> {
    let value_sha256 = sha256_hex(leaf.status_value_bytes);
    let local_intent = load_intent_by_finding_tx(transaction, epoch.feed_id, leaf.finding_id)?;
    if let (Some(requested), Some(existing)) = (leaf.local_intent_id, local_intent.as_ref()) {
        if requested != existing.intent_id {
            return Err(FindingStatusStoreError::Conflict(format!(
                "leaf for {} names a different local intent",
                leaf.finding_id
            )));
        }
    }
    if leaf.local_intent_id.is_some() && local_intent.is_none() {
        return Err(FindingStatusStoreError::Conflict(format!(
            "leaf for {} names a missing local intent",
            leaf.finding_id
        )));
    }
    let effective_intent_id = local_intent
        .as_ref()
        .map(|intent| intent.intent_id.as_str())
        .or(leaf.local_intent_id);
    if let Some(intent) = local_intent.as_ref() {
        if intent.operator_id != epoch.operator_id
            || intent.finding_id != leaf.finding_id
            || intent.intent_sha256 != leaf.retraction_intent_sha256
        {
            return Err(FindingStatusStoreError::Conflict(format!(
                "leaf for {} does not match its durable intent",
                leaf.finding_id
            )));
        }
        if intent.state == FindingRetractionIntentState::WaitingFinality {
            return Err(FindingStatusStoreError::Conflict(format!(
                "retraction intent {} is not dispatch eligible",
                intent.intent_id
            )));
        }
        if intent
            .dispatch_eligible_at
            .is_some_and(|eligible_at| epoch.recorded_at < eligible_at)
        {
            return Err(invariant("status epoch predates dispatch eligibility"));
        }
    }

    let mut outcome = FindingStatusWriteOutcome::Inserted;
    if let Some(existing) = load_leaf_tx(transaction, epoch.feed_id, leaf.finding_id)? {
        if existing.operator_id != epoch.operator_id
            || existing.key_domain_nonce != epoch.key_domain_nonce
            || existing.status_value_sha256 != value_sha256
            || existing.status_value_bytes != leaf.status_value_bytes
            || existing.retraction_intent_sha256 != leaf.retraction_intent_sha256
            || (existing.local_intent_id.is_some()
                && existing.local_intent_id.as_deref() != effective_intent_id)
        {
            return Err(FindingStatusStoreError::Conflict(format!(
                "finding {} already has a different sticky leaf",
                leaf.finding_id
            )));
        }
        outcome = FindingStatusWriteOutcome::ExactReplay;
    } else {
        transaction
            .execute(
                r#"
                INSERT INTO finding_status_leaves (
                    feed_id, operator_id, finding_id, key_domain_nonce,
                    status_value_sha256, status_value_bytes,
                    retraction_intent_sha256, local_intent_id,
                    first_map_epoch, first_epoch_id, recorded_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                "#,
                params![
                    epoch.feed_id,
                    epoch.operator_id,
                    leaf.finding_id,
                    sqlite_i64(epoch.key_domain_nonce, "key_domain_nonce")?,
                    value_sha256,
                    leaf.status_value_bytes,
                    leaf.retraction_intent_sha256,
                    effective_intent_id,
                    sqlite_i64(epoch.map_epoch, "map_epoch")?,
                    epoch.epoch_id,
                    sqlite_i64(epoch.recorded_at, "recorded_at")?,
                ],
            )
            .map_err(sqlite_error)?;
    }

    match load_status_tx(transaction, epoch.feed_id, leaf.finding_id)? {
        Some(status) if status.retraction_intent_sha256 != leaf.retraction_intent_sha256 => {
            return Err(FindingStatusStoreError::Conflict(format!(
                "finding {} has a different sticky intent digest",
                leaf.finding_id
            )));
        }
        Some(status) if status.state == FindingStickyStatus::Pending => {
            transaction
                .execute(
                    r#"
                    UPDATE finding_status_states
                    SET state = 'retracted', updated_at = ?3,
                        retracted_map_epoch = ?4, retracted_epoch_id = ?5,
                        retracted_root_hash = ?6
                    WHERE feed_id = ?1 AND finding_id = ?2 AND state = 'pending'
                    "#,
                    params![
                        epoch.feed_id,
                        leaf.finding_id,
                        sqlite_i64(epoch.recorded_at, "recorded_at")?,
                        sqlite_i64(epoch.map_epoch, "map_epoch")?,
                        epoch.epoch_id,
                        epoch.root_hash,
                    ],
                )
                .map_err(sqlite_error)?;
        }
        Some(_) => {}
        None => {
            transaction
                .execute(
                    r#"
                    INSERT INTO finding_status_states (
                        feed_id, operator_id, finding_id, state,
                        retraction_intent_sha256, first_observed_at, updated_at,
                        retracted_map_epoch, retracted_epoch_id,
                        retracted_root_hash
                    ) VALUES (?1, ?2, ?3, 'retracted', ?4, ?5, ?5, ?6, ?7, ?8)
                    "#,
                    params![
                        epoch.feed_id,
                        epoch.operator_id,
                        leaf.finding_id,
                        leaf.retraction_intent_sha256,
                        sqlite_i64(epoch.recorded_at, "recorded_at")?,
                        sqlite_i64(epoch.map_epoch, "map_epoch")?,
                        epoch.epoch_id,
                        epoch.root_hash,
                    ],
                )
                .map_err(sqlite_error)?;
        }
    }

    if let Some(intent) = local_intent {
        match intent.state {
            FindingRetractionIntentState::DispatchEligible => {
                transaction
                    .execute(
                        r#"
                        UPDATE finding_retraction_intents
                        SET state = 'published', published_map_epoch = ?2,
                            published_epoch_id = ?3, updated_at = ?4
                        WHERE intent_id = ?1 AND state = 'dispatch_eligible'
                        "#,
                        params![
                            intent.intent_id,
                            sqlite_i64(epoch.map_epoch, "map_epoch")?,
                            epoch.epoch_id,
                            sqlite_i64(epoch.recorded_at, "recorded_at")?,
                        ],
                    )
                    .map_err(sqlite_error)?;
            }
            FindingRetractionIntentState::Published => {
                if intent.published_map_epoch != Some(epoch.map_epoch)
                    && intent
                        .published_map_epoch
                        .is_some_and(|published| published > epoch.map_epoch)
                {
                    return Err(FindingStatusStoreError::Rollback {
                        feed_id: epoch.feed_id.to_owned(),
                        current: intent.published_map_epoch.unwrap_or(epoch.map_epoch),
                        proposed: epoch.map_epoch,
                    });
                }
            }
            FindingRetractionIntentState::WaitingFinality => {
                return Err(invariant(
                    "waiting-finality intent reached leaf publication",
                ));
            }
        }
    }
    Ok(outcome)
}

pub(super) fn persist_conflicting_retraction_tx(
    transaction: &Transaction<'_>,
    proof: &VerifiedFindingStatusProofInput<'_>,
) -> Result<FindingStatusWriteOutcome, FindingStatusStoreError> {
    let intent_sha256 = proof
        .retraction_intent_sha256
        .ok_or_else(|| invariant("conflicting-epoch retraction lost its intent digest"))?;
    match load_status_tx(transaction, proof.feed_id, proof.finding_id)? {
        Some(status) if status.retraction_intent_sha256 != intent_sha256 => {
            Err(FindingStatusStoreError::Conflict(format!(
                "finding {} has a different sticky intent digest",
                proof.finding_id
            )))
        }
        Some(status) if status.state == FindingStickyStatus::Pending => {
            if proof.recorded_at < status.first_observed_at {
                return Err(invariant(
                    "conflicting-epoch retraction predates its pending status",
                ));
            }
            transaction
                .execute(
                    r#"
                    UPDATE finding_status_states
                    SET state = 'retracted', updated_at = ?3,
                        retracted_map_epoch = ?4, retracted_epoch_id = ?5,
                        retracted_root_hash = ?6
                    WHERE feed_id = ?1 AND finding_id = ?2 AND state = 'pending'
                    "#,
                    params![
                        proof.feed_id,
                        proof.finding_id,
                        sqlite_i64(proof.recorded_at, "recorded_at")?,
                        sqlite_i64(proof.map_epoch, "map_epoch")?,
                        proof.epoch_id,
                        proof.root_hash,
                    ],
                )
                .map_err(sqlite_error)?;
            Ok(FindingStatusWriteOutcome::Inserted)
        }
        Some(_) => Ok(FindingStatusWriteOutcome::ExactReplay),
        None => {
            transaction
                .execute(
                    r#"
                    INSERT INTO finding_status_states (
                        feed_id, operator_id, finding_id, state,
                        retraction_intent_sha256, first_observed_at, updated_at,
                        retracted_map_epoch, retracted_epoch_id,
                        retracted_root_hash
                    ) VALUES (?1, ?2, ?3, 'retracted', ?4, ?5, ?5, ?6, ?7, ?8)
                    "#,
                    params![
                        proof.feed_id,
                        proof.operator_id,
                        proof.finding_id,
                        intent_sha256,
                        sqlite_i64(proof.recorded_at, "recorded_at")?,
                        sqlite_i64(proof.map_epoch, "map_epoch")?,
                        proof.epoch_id,
                        proof.root_hash,
                    ],
                )
                .map_err(sqlite_error)?;
            Ok(FindingStatusWriteOutcome::Inserted)
        }
    }
}

pub(super) fn persist_proof_tx(
    transaction: &Transaction<'_>,
    proof: &VerifiedFindingStatusProofInput<'_>,
) -> Result<FindingStatusWriteOutcome, FindingStatusStoreError> {
    let epoch = load_epoch_tx(transaction, proof.feed_id, proof.map_epoch)?
        .ok_or_else(|| invariant("proof names a missing signed epoch"))?;
    if epoch.operator_id != proof.operator_id
        || epoch.key_domain_nonce != proof.key_domain_nonce
        || epoch.epoch_id != proof.epoch_id
        || epoch.root_hash != proof.root_hash
    {
        return Err(invariant("proof does not match its retained signed epoch"));
    }
    if proof.valid_until > epoch.valid_until {
        return Err(invariant("proof freshness exceeds its retained epoch"));
    }

    match proof.kind {
        FindingStatusProofKind::NonInclusion => {
            if load_status_tx(transaction, proof.feed_id, proof.finding_id)?.is_some() {
                return Err(FindingStatusStoreError::ContradictoryNonInclusion {
                    finding_id: proof.finding_id.to_owned(),
                });
            }
        }
        FindingStatusProofKind::Inclusion => {
            let leaf = VerifiedFindingStatusLeafInput {
                finding_id: proof.finding_id,
                status_value_bytes: proof
                    .status_value_bytes
                    .ok_or_else(|| invariant("inclusion proof lost its exact status value"))?,
                retraction_intent_sha256: proof
                    .retraction_intent_sha256
                    .ok_or_else(|| invariant("inclusion proof lost its intent digest"))?,
                local_intent_id: None,
            };
            persist_leaf_tx(transaction, &epoch_as_input(&epoch), &leaf)?;
        }
    }

    let proof_sha256 = sha256_hex(proof.proof_bytes);
    let status_value_sha256 = proof.status_value_bytes.map(sha256_hex);
    if let Some(existing) = load_proof_tx(
        transaction,
        proof.feed_id,
        proof.finding_id,
        proof.map_epoch,
    )? {
        if proof_record_matches_input(
            &existing,
            proof,
            &proof_sha256,
            status_value_sha256.as_deref(),
        ) {
            return Ok(FindingStatusWriteOutcome::ExactReplay);
        }
        return Err(FindingStatusStoreError::Conflict(format!(
            "finding {} has a different proof at map epoch {}",
            proof.finding_id, proof.map_epoch
        )));
    }

    transaction
        .execute(
            r#"
            INSERT INTO finding_status_proofs (
                feed_id, operator_id, finding_id, key_domain_nonce, map_epoch,
                epoch_id, root_hash, proof_kind, proof_sha256, proof_bytes,
                status_value_sha256, status_value_bytes,
                retraction_intent_sha256, checked_at, valid_until, recorded_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                      ?12, ?13, ?14, ?15, ?16)
            "#,
            params![
                proof.feed_id,
                proof.operator_id,
                proof.finding_id,
                sqlite_i64(proof.key_domain_nonce, "key_domain_nonce")?,
                sqlite_i64(proof.map_epoch, "map_epoch")?,
                proof.epoch_id,
                proof.root_hash,
                proof_kind_name(proof.kind),
                proof_sha256,
                proof.proof_bytes,
                status_value_sha256,
                proof.status_value_bytes,
                proof.retraction_intent_sha256,
                sqlite_i64(proof.checked_at, "checked_at")?,
                sqlite_i64(proof.valid_until, "valid_until")?,
                sqlite_i64(proof.recorded_at, "recorded_at")?,
            ],
        )
        .map_err(sqlite_error)?;
    transaction
        .execute(
            "DELETE FROM finding_status_proofs \
             WHERE feed_id = ?1 AND finding_id = ?2 AND map_epoch < ?3",
            params![
                proof.feed_id,
                proof.finding_id,
                sqlite_i64(proof.map_epoch, "map_epoch")?,
            ],
        )
        .map_err(sqlite_error)?;
    Ok(FindingStatusWriteOutcome::Inserted)
}

pub(super) fn ensure_feed_tx(
    transaction: &Transaction<'_>,
    feed_id: &str,
    operator_id: &str,
    registered_at: u64,
) -> Result<(), FindingStatusStoreError> {
    let existing = transaction
        .query_row(
            "SELECT operator_id, key_domain_nonce FROM finding_status_feeds WHERE feed_id = ?1",
            [feed_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    match existing {
        Some((stored_operator, stored_nonce)) => {
            if stored_operator != operator_id
                || stored_u64(stored_nonce, "key_domain_nonce")? != FINDING_STATUS_KEY_DOMAIN_NONCE
            {
                return Err(FindingStatusStoreError::Conflict(format!(
                    "feed {feed_id} is bound to a different operator identity"
                )));
            }
        }
        None => {
            transaction
                .execute(
                    r#"
                    INSERT INTO finding_status_feeds (
                        feed_id, operator_id, key_domain_nonce, registered_at
                    ) VALUES (?1, ?2, ?3, ?4)
                    "#,
                    params![
                        feed_id,
                        operator_id,
                        sqlite_i64(FINDING_STATUS_KEY_DOMAIN_NONCE, "key_domain_nonce")?,
                        sqlite_i64(registered_at, "registered_at")?,
                    ],
                )
                .map_err(sqlite_error)?;
        }
    }
    Ok(())
}

pub(super) fn ensure_feed_exists_tx(
    transaction: &Transaction<'_>,
    feed_id: &str,
    operator_id: &str,
) -> Result<(), FindingStatusStoreError> {
    let existing = transaction
        .query_row(
            "SELECT operator_id, key_domain_nonce FROM finding_status_feeds WHERE feed_id = ?1",
            [feed_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or_else(|| {
            FindingStatusStoreError::Conflict(format!("feed {feed_id} is not registered"))
        })?;
    if existing.0 != operator_id
        || stored_u64(existing.1, "key_domain_nonce")? != FINDING_STATUS_KEY_DOMAIN_NONCE
    {
        return Err(FindingStatusStoreError::Conflict(format!(
            "feed {feed_id} is bound to a different operator identity"
        )));
    }
    Ok(())
}

pub(super) fn ensure_feed_registered_tx(
    transaction: &Transaction<'_>,
    feed_id: &str,
) -> Result<(), FindingStatusStoreError> {
    let exists = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM finding_status_feeds WHERE feed_id = ?1)",
            [feed_id],
            |row| row.get::<_, bool>(0),
        )
        .map_err(sqlite_error)?;
    if !exists {
        return Err(FindingStatusStoreError::MissingFloor {
            feed_id: feed_id.to_owned(),
        });
    }
    Ok(())
}

pub(super) fn feed_has_epochs_tx(
    transaction: &Transaction<'_>,
    feed_id: &str,
) -> Result<bool, FindingStatusStoreError> {
    transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM finding_status_epochs WHERE feed_id = ?1)",
            [feed_id],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}
