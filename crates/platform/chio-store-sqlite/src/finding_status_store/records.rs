//! Row decoding, bounded loads and record checks for finding status epochs,
//! floors, intents, statuses, leaves and proofs.

use super::*;

#[derive(Debug)]
pub(super) struct RawEpoch {
    feed_id: String,
    operator_id: String,
    key_domain_nonce: i64,
    map_epoch: i64,
    epoch_id: String,
    root_hash: String,
    signed_epoch_sha256: String,
    signed_epoch_bytes: Vec<u8>,
    operator_key: String,
    operator_key_epoch: i64,
    operator_authorization_sha256: String,
    generated_at: i64,
    valid_until: i64,
    recorded_at: i64,
}

pub(super) fn raw_epoch_from_row(row: &Row<'_>) -> rusqlite::Result<RawEpoch> {
    Ok(RawEpoch {
        feed_id: row.get(0)?,
        operator_id: row.get(1)?,
        key_domain_nonce: row.get(2)?,
        map_epoch: row.get(3)?,
        epoch_id: row.get(4)?,
        root_hash: row.get(5)?,
        signed_epoch_sha256: row.get(6)?,
        signed_epoch_bytes: row.get(7)?,
        operator_key: row.get(8)?,
        operator_key_epoch: row.get(9)?,
        operator_authorization_sha256: row.get(10)?,
        generated_at: row.get(11)?,
        valid_until: row.get(12)?,
        recorded_at: row.get(13)?,
    })
}

pub(super) fn epoch_from_raw(
    raw: RawEpoch,
) -> Result<FindingStatusEpochRecord, FindingStatusStoreError> {
    require_fixed_nonce(stored_u64(raw.key_domain_nonce, "key_domain_nonce")?)?;
    require_hex64(&raw.epoch_id, "epoch_id")?;
    require_hex64(&raw.root_hash, "root_hash")?;
    require_hex64(&raw.signed_epoch_sha256, "signed_epoch_sha256")?;
    require_bytes(
        &raw.signed_epoch_bytes,
        MAX_FINDING_STATUS_EPOCH_BYTES,
        "signed_epoch_bytes",
    )?;
    if sha256_hex(&raw.signed_epoch_bytes) != raw.signed_epoch_sha256 {
        return Err(invariant("retained signed epoch bytes fail their digest"));
    }
    require_hex64(
        &raw.operator_authorization_sha256,
        "operator_authorization_sha256",
    )?;
    Ok(FindingStatusEpochRecord {
        feed_id: raw.feed_id,
        operator_id: raw.operator_id,
        key_domain_nonce: stored_u64(raw.key_domain_nonce, "key_domain_nonce")?,
        map_epoch: stored_u64(raw.map_epoch, "map_epoch")?,
        epoch_id: raw.epoch_id,
        root_hash: raw.root_hash,
        signed_epoch_sha256: raw.signed_epoch_sha256,
        signed_epoch_bytes: raw.signed_epoch_bytes,
        operator_key: raw.operator_key,
        operator_key_epoch: stored_u64(raw.operator_key_epoch, "operator_key_epoch")?,
        operator_authorization_sha256: raw.operator_authorization_sha256,
        generated_at: stored_u64(raw.generated_at, "generated_at")?,
        valid_until: stored_u64(raw.valid_until, "valid_until")?,
        recorded_at: stored_u64(raw.recorded_at, "recorded_at")?,
    })
}

pub(super) fn load_epoch_tx(
    transaction: &Transaction<'_>,
    feed_id: &str,
    map_epoch: u64,
) -> Result<Option<FindingStatusEpochRecord>, FindingStatusStoreError> {
    let raw = transaction
        .query_row(
            r#"
            SELECT feed_id, operator_id, key_domain_nonce, map_epoch, epoch_id,
                   root_hash, signed_epoch_sha256, signed_epoch_bytes,
                   operator_key, operator_key_epoch,
                   operator_authorization_sha256, generated_at, valid_until,
                   recorded_at
            FROM finding_status_epochs
            WHERE feed_id = ?1 AND map_epoch = ?2
            "#,
            params![feed_id, sqlite_i64(map_epoch, "map_epoch")?],
            raw_epoch_from_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(epoch_from_raw).transpose()
}

pub(super) fn epoch_as_input(
    epoch: &FindingStatusEpochRecord,
) -> VerifiedFindingStatusEpochInput<'_> {
    VerifiedFindingStatusEpochInput {
        feed_id: &epoch.feed_id,
        operator_id: &epoch.operator_id,
        key_domain_nonce: epoch.key_domain_nonce,
        map_epoch: epoch.map_epoch,
        epoch_id: &epoch.epoch_id,
        root_hash: &epoch.root_hash,
        signed_epoch_bytes: &epoch.signed_epoch_bytes,
        operator_key: &epoch.operator_key,
        operator_key_epoch: epoch.operator_key_epoch,
        operator_authorization_sha256: &epoch.operator_authorization_sha256,
        generated_at: epoch.generated_at,
        valid_until: epoch.valid_until,
        recorded_at: epoch.recorded_at,
    }
}

pub(super) fn epoch_record_matches_input(
    record: &FindingStatusEpochRecord,
    input: &VerifiedFindingStatusEpochInput<'_>,
    signed_epoch_sha256: &str,
) -> bool {
    record.feed_id == input.feed_id
        && record.operator_id == input.operator_id
        && record.key_domain_nonce == input.key_domain_nonce
        && record.map_epoch == input.map_epoch
        && record.epoch_id == input.epoch_id
        && record.root_hash == input.root_hash
        && record.signed_epoch_sha256 == signed_epoch_sha256
        && record.signed_epoch_bytes == input.signed_epoch_bytes
        && record.operator_key == input.operator_key
        && record.operator_key_epoch == input.operator_key_epoch
        && record.operator_authorization_sha256 == input.operator_authorization_sha256
        && record.generated_at == input.generated_at
        && record.valid_until == input.valid_until
}

#[derive(Debug)]
pub(super) struct RawFloor {
    feed_id: String,
    operator_id: String,
    key_domain_nonce: i64,
    map_epoch: i64,
    epoch_id: String,
    root_hash: String,
    signed_epoch_sha256: String,
    operator_key: String,
    operator_key_epoch: i64,
    operator_authorization_sha256: String,
    advanced_at: i64,
}

pub(super) fn raw_floor_from_row(row: &Row<'_>) -> rusqlite::Result<RawFloor> {
    Ok(RawFloor {
        feed_id: row.get(0)?,
        operator_id: row.get(1)?,
        key_domain_nonce: row.get(2)?,
        map_epoch: row.get(3)?,
        epoch_id: row.get(4)?,
        root_hash: row.get(5)?,
        signed_epoch_sha256: row.get(6)?,
        operator_key: row.get(7)?,
        operator_key_epoch: row.get(8)?,
        operator_authorization_sha256: row.get(9)?,
        advanced_at: row.get(10)?,
    })
}

pub(super) fn floor_from_raw(
    raw: RawFloor,
) -> Result<FindingStatusFeedFloor, FindingStatusStoreError> {
    let nonce = stored_u64(raw.key_domain_nonce, "key_domain_nonce")?;
    require_fixed_nonce(nonce)?;
    require_hex64(&raw.epoch_id, "epoch_id")?;
    require_hex64(&raw.root_hash, "root_hash")?;
    require_hex64(&raw.signed_epoch_sha256, "signed_epoch_sha256")?;
    require_hex64(
        &raw.operator_authorization_sha256,
        "operator_authorization_sha256",
    )?;
    Ok(FindingStatusFeedFloor {
        feed_id: raw.feed_id,
        operator_id: raw.operator_id,
        key_domain_nonce: nonce,
        map_epoch: stored_u64(raw.map_epoch, "map_epoch")?,
        epoch_id: raw.epoch_id,
        root_hash: raw.root_hash,
        signed_epoch_sha256: raw.signed_epoch_sha256,
        operator_key: raw.operator_key,
        operator_key_epoch: stored_u64(raw.operator_key_epoch, "operator_key_epoch")?,
        operator_authorization_sha256: raw.operator_authorization_sha256,
        advanced_at: stored_u64(raw.advanced_at, "advanced_at")?,
    })
}

pub(super) fn load_floor_tx(
    transaction: &Transaction<'_>,
    feed_id: &str,
) -> Result<Option<FindingStatusFeedFloor>, FindingStatusStoreError> {
    let raw = transaction
        .query_row(
            r#"
            SELECT feed_id, operator_id, key_domain_nonce, map_epoch, epoch_id,
                   root_hash, signed_epoch_sha256, operator_key,
                   operator_key_epoch, operator_authorization_sha256,
                   advanced_at
            FROM finding_status_feed_floors
            WHERE feed_id = ?1
            "#,
            [feed_id],
            raw_floor_from_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(floor_from_raw).transpose()
}

pub(super) fn advance_trusted_time_floor_tx(
    transaction: &Transaction<'_>,
    feed_id: &str,
    trusted_now: u64,
) -> Result<FindingStatusWriteOutcome, FindingStatusStoreError> {
    let floor = load_floor_tx(transaction, feed_id)?.ok_or_else(|| {
        FindingStatusStoreError::MissingFloor {
            feed_id: feed_id.to_owned(),
        }
    })?;
    if trusted_now < floor.advanced_at {
        return Err(FindingStatusStoreError::ClockRollback {
            feed_id: feed_id.to_owned(),
            high_water: floor.advanced_at,
            observed: trusted_now,
        });
    }
    if trusted_now == floor.advanced_at {
        return Ok(FindingStatusWriteOutcome::ExactReplay);
    }
    let changed = transaction
        .execute(
            "UPDATE finding_status_feed_floors SET advanced_at = ?2 WHERE feed_id = ?1 AND advanced_at = ?3",
            params![
                feed_id,
                sqlite_i64(trusted_now, "trusted_now")?,
                sqlite_i64(floor.advanced_at, "advanced_at")?,
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(invariant("finding status clock floor changed concurrently"));
    }
    Ok(FindingStatusWriteOutcome::Inserted)
}

pub(super) fn verify_floor_epoch_consistency(
    floor: &FindingStatusFeedFloor,
    epoch: &FindingStatusEpochRecord,
) -> Result<(), FindingStatusStoreError> {
    if floor.feed_id != epoch.feed_id
        || floor.operator_id != epoch.operator_id
        || floor.key_domain_nonce != epoch.key_domain_nonce
        || floor.map_epoch != epoch.map_epoch
        || floor.epoch_id != epoch.epoch_id
        || floor.root_hash != epoch.root_hash
        || floor.signed_epoch_sha256 != epoch.signed_epoch_sha256
        || floor.operator_key != epoch.operator_key
        || floor.operator_key_epoch != epoch.operator_key_epoch
        || floor.operator_authorization_sha256 != epoch.operator_authorization_sha256
    {
        return Err(invariant(
            "durable status floor does not match its retained signed epoch",
        ));
    }
    Ok(())
}

#[derive(Debug)]
pub(super) struct RawIntent {
    intent_id: String,
    feed_id: String,
    operator_id: String,
    finding_id: String,
    source: String,
    intent_sha256: String,
    intent_bytes: Vec<u8>,
    issued_at: i64,
    inclusion_deadline: i64,
    state: String,
    finality_evidence_sha256: Option<String>,
    finality_evidence_bytes: Option<Vec<u8>>,
    dispatch_eligible_at: Option<i64>,
    published_map_epoch: Option<i64>,
    published_epoch_id: Option<String>,
    created_at: i64,
    updated_at: i64,
}

pub(super) fn raw_intent_from_row(row: &Row<'_>) -> rusqlite::Result<RawIntent> {
    Ok(RawIntent {
        intent_id: row.get(0)?,
        feed_id: row.get(1)?,
        operator_id: row.get(2)?,
        finding_id: row.get(3)?,
        source: row.get(4)?,
        intent_sha256: row.get(5)?,
        intent_bytes: row.get(6)?,
        issued_at: row.get(7)?,
        inclusion_deadline: row.get(8)?,
        state: row.get(9)?,
        finality_evidence_sha256: row.get(10)?,
        finality_evidence_bytes: row.get(11)?,
        dispatch_eligible_at: row.get(12)?,
        published_map_epoch: row.get(13)?,
        published_epoch_id: row.get(14)?,
        created_at: row.get(15)?,
        updated_at: row.get(16)?,
    })
}

pub(super) fn intent_from_raw(
    raw: RawIntent,
) -> Result<FindingRetractionIntentRecord, FindingStatusStoreError> {
    require_hex64(&raw.intent_id, "intent_id")?;
    require_hex64(&raw.finding_id, "finding_id")?;
    require_hex64(&raw.intent_sha256, "intent_sha256")?;
    require_bytes(
        &raw.intent_bytes,
        MAX_FINDING_RETRACTION_EVIDENCE_BYTES,
        "intent_bytes",
    )?;
    if sha256_hex(&raw.intent_bytes) != raw.intent_sha256 {
        return Err(invariant("retained retraction intent fails its digest"));
    }
    if let Some(digest) = raw.finality_evidence_sha256.as_deref() {
        require_hex64(digest, "finality_evidence_sha256")?;
    }
    if let Some(bytes) = raw.finality_evidence_bytes.as_deref() {
        require_bytes(
            bytes,
            MAX_FINDING_RETRACTION_EVIDENCE_BYTES,
            "finality_evidence_bytes",
        )?;
        if raw.finality_evidence_sha256.as_deref() != Some(sha256_hex(bytes).as_str()) {
            return Err(invariant("retained finality evidence fails its digest"));
        }
    }
    let record = FindingRetractionIntentRecord {
        intent_id: raw.intent_id,
        feed_id: raw.feed_id,
        operator_id: raw.operator_id,
        finding_id: raw.finding_id,
        source: intent_source_from_name(&raw.source)?,
        intent_sha256: raw.intent_sha256,
        intent_bytes: raw.intent_bytes,
        issued_at: stored_u64(raw.issued_at, "issued_at")?,
        inclusion_deadline: stored_u64(raw.inclusion_deadline, "inclusion_deadline")?,
        state: intent_state_from_name(&raw.state)?,
        finality_evidence_sha256: raw.finality_evidence_sha256,
        finality_evidence_bytes: raw.finality_evidence_bytes,
        dispatch_eligible_at: stored_optional_u64(
            raw.dispatch_eligible_at,
            "dispatch_eligible_at",
        )?,
        published_map_epoch: stored_optional_u64(raw.published_map_epoch, "published_map_epoch")?,
        published_epoch_id: raw.published_epoch_id,
        created_at: stored_u64(raw.created_at, "created_at")?,
        updated_at: stored_u64(raw.updated_at, "updated_at")?,
    };
    verify_intent_record_shape(&record)?;
    Ok(record)
}

pub(super) fn verify_intent_record_shape(
    record: &FindingRetractionIntentRecord,
) -> Result<(), FindingStatusStoreError> {
    match record.state {
        FindingRetractionIntentState::WaitingFinality => {
            if record.finality_evidence_sha256.is_some()
                || record.finality_evidence_bytes.is_some()
                || record.dispatch_eligible_at.is_some()
                || record.published_map_epoch.is_some()
                || record.published_epoch_id.is_some()
            {
                return Err(invariant("waiting-finality intent has later-state fields"));
            }
        }
        FindingRetractionIntentState::DispatchEligible => {
            if record.finality_evidence_sha256.is_none()
                || record.finality_evidence_bytes.is_none()
                || record.dispatch_eligible_at.is_none()
                || record.published_map_epoch.is_some()
                || record.published_epoch_id.is_some()
            {
                return Err(invariant(
                    "dispatch-eligible intent has inconsistent lifecycle fields",
                ));
            }
        }
        FindingRetractionIntentState::Published => {
            if record.finality_evidence_sha256.is_none()
                || record.finality_evidence_bytes.is_none()
                || record.dispatch_eligible_at.is_none()
                || record.published_map_epoch.is_none()
                || record.published_epoch_id.is_none()
            {
                return Err(invariant(
                    "published intent has inconsistent lifecycle fields",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn load_intent_tx(
    transaction: &Transaction<'_>,
    intent_id: &str,
) -> Result<Option<FindingRetractionIntentRecord>, FindingStatusStoreError> {
    let raw = transaction
        .query_row(
            r#"
            SELECT intent_id, feed_id, operator_id, finding_id, source,
                   intent_sha256, intent_bytes, issued_at, inclusion_deadline,
                   state, finality_evidence_sha256, finality_evidence_bytes,
                   dispatch_eligible_at, published_map_epoch,
                   published_epoch_id, created_at, updated_at
            FROM finding_retraction_intents
            WHERE intent_id = ?1
            "#,
            [intent_id],
            raw_intent_from_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(intent_from_raw).transpose()
}

pub(super) fn load_intent_by_finding_tx(
    transaction: &Transaction<'_>,
    feed_id: &str,
    finding_id: &str,
) -> Result<Option<FindingRetractionIntentRecord>, FindingStatusStoreError> {
    let raw = transaction
        .query_row(
            r#"
            SELECT intent_id, feed_id, operator_id, finding_id, source,
                   intent_sha256, intent_bytes, issued_at, inclusion_deadline,
                   state, finality_evidence_sha256, finality_evidence_bytes,
                   dispatch_eligible_at, published_map_epoch,
                   published_epoch_id, created_at, updated_at
            FROM finding_retraction_intents
            WHERE feed_id = ?1 AND finding_id = ?2
            "#,
            params![feed_id, finding_id],
            raw_intent_from_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(intent_from_raw).transpose()
}

pub(super) fn verify_intent_replay(
    record: &FindingRetractionIntentRecord,
    input: &FindingRetractionIntentInput<'_>,
    intent_sha256: &str,
) -> Result<(), FindingStatusStoreError> {
    if record.feed_id != input.feed_id
        || record.operator_id != input.operator_id
        || record.finding_id != input.finding_id
        || record.source != input.source
        || record.intent_sha256 != intent_sha256
        || record.intent_bytes != input.intent_bytes
        || record.issued_at != input.issued_at
        || record.inclusion_deadline != input.inclusion_deadline
    {
        return Err(FindingStatusStoreError::Conflict(format!(
            "retraction intent {} was replayed with different bytes or bindings",
            input.intent_id
        )));
    }
    Ok(())
}

pub(super) fn verify_intent_status_pair(
    intent: &FindingRetractionIntentRecord,
    status: &FindingStatusRecord,
) -> Result<(), FindingStatusStoreError> {
    if intent.feed_id != status.feed_id
        || intent.operator_id != status.operator_id
        || intent.finding_id != status.finding_id
        || intent.intent_sha256 != status.retraction_intent_sha256
        || (intent.state != FindingRetractionIntentState::Published
            && status.state != FindingStickyStatus::Pending)
        || (intent.state == FindingRetractionIntentState::Published
            && status.state != FindingStickyStatus::Retracted)
    {
        return Err(invariant(
            "retraction intent does not match its sticky status row",
        ));
    }
    Ok(())
}

#[derive(Debug)]
pub(super) struct RawStatus {
    feed_id: String,
    operator_id: String,
    finding_id: String,
    state: String,
    retraction_intent_sha256: String,
    first_observed_at: i64,
    updated_at: i64,
    retracted_map_epoch: Option<i64>,
    retracted_epoch_id: Option<String>,
    retracted_root_hash: Option<String>,
}

pub(super) fn raw_status_from_row(row: &Row<'_>) -> rusqlite::Result<RawStatus> {
    Ok(RawStatus {
        feed_id: row.get(0)?,
        operator_id: row.get(1)?,
        finding_id: row.get(2)?,
        state: row.get(3)?,
        retraction_intent_sha256: row.get(4)?,
        first_observed_at: row.get(5)?,
        updated_at: row.get(6)?,
        retracted_map_epoch: row.get(7)?,
        retracted_epoch_id: row.get(8)?,
        retracted_root_hash: row.get(9)?,
    })
}

pub(super) fn status_from_raw(
    raw: RawStatus,
) -> Result<FindingStatusRecord, FindingStatusStoreError> {
    require_hex64(&raw.finding_id, "finding_id")?;
    require_hex64(&raw.retraction_intent_sha256, "retraction_intent_sha256")?;
    if let Some(epoch_id) = raw.retracted_epoch_id.as_deref() {
        require_hex64(epoch_id, "retracted_epoch_id")?;
    }
    if let Some(root_hash) = raw.retracted_root_hash.as_deref() {
        require_hex64(root_hash, "retracted_root_hash")?;
    }
    let record = FindingStatusRecord {
        feed_id: raw.feed_id,
        operator_id: raw.operator_id,
        finding_id: raw.finding_id,
        state: sticky_status_from_name(&raw.state)?,
        retraction_intent_sha256: raw.retraction_intent_sha256,
        first_observed_at: stored_u64(raw.first_observed_at, "first_observed_at")?,
        updated_at: stored_u64(raw.updated_at, "updated_at")?,
        retracted_map_epoch: stored_optional_u64(raw.retracted_map_epoch, "retracted_map_epoch")?,
        retracted_epoch_id: raw.retracted_epoch_id,
        retracted_root_hash: raw.retracted_root_hash,
    };
    match record.state {
        FindingStickyStatus::Pending
            if record.retracted_map_epoch.is_some()
                || record.retracted_epoch_id.is_some()
                || record.retracted_root_hash.is_some() =>
        {
            Err(invariant("pending status has retracted epoch fields"))
        }
        FindingStickyStatus::Retracted
            if record.retracted_map_epoch.is_none()
                || record.retracted_epoch_id.is_none()
                || record.retracted_root_hash.is_none() =>
        {
            Err(invariant("retracted status is missing epoch fields"))
        }
        _ => Ok(record),
    }
}

pub(super) fn load_status_tx(
    transaction: &Transaction<'_>,
    feed_id: &str,
    finding_id: &str,
) -> Result<Option<FindingStatusRecord>, FindingStatusStoreError> {
    let raw = transaction
        .query_row(
            r#"
            SELECT feed_id, operator_id, finding_id, state,
                   retraction_intent_sha256, first_observed_at, updated_at,
                   retracted_map_epoch, retracted_epoch_id,
                   retracted_root_hash
            FROM finding_status_states
            WHERE feed_id = ?1 AND finding_id = ?2
            "#,
            params![feed_id, finding_id],
            raw_status_from_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(status_from_raw).transpose()
}

#[derive(Debug)]
pub(super) struct RawLeaf {
    feed_id: String,
    operator_id: String,
    finding_id: String,
    key_domain_nonce: i64,
    status_value_sha256: String,
    status_value_bytes: Vec<u8>,
    retraction_intent_sha256: String,
    local_intent_id: Option<String>,
    first_map_epoch: i64,
    first_epoch_id: String,
    recorded_at: i64,
}

pub(super) fn raw_leaf_from_row(row: &Row<'_>) -> rusqlite::Result<RawLeaf> {
    Ok(RawLeaf {
        feed_id: row.get(0)?,
        operator_id: row.get(1)?,
        finding_id: row.get(2)?,
        key_domain_nonce: row.get(3)?,
        status_value_sha256: row.get(4)?,
        status_value_bytes: row.get(5)?,
        retraction_intent_sha256: row.get(6)?,
        local_intent_id: row.get(7)?,
        first_map_epoch: row.get(8)?,
        first_epoch_id: row.get(9)?,
        recorded_at: row.get(10)?,
    })
}

pub(super) fn leaf_from_raw(
    raw: RawLeaf,
) -> Result<FindingStatusLeafRecord, FindingStatusStoreError> {
    let nonce = stored_u64(raw.key_domain_nonce, "key_domain_nonce")?;
    require_fixed_nonce(nonce)?;
    require_hex64(&raw.finding_id, "finding_id")?;
    require_hex64(&raw.status_value_sha256, "status_value_sha256")?;
    require_bytes(
        &raw.status_value_bytes,
        MAX_FINDING_STATUS_VALUE_BYTES,
        "status_value_bytes",
    )?;
    if sha256_hex(&raw.status_value_bytes) != raw.status_value_sha256 {
        return Err(invariant("retained status leaf fails its value digest"));
    }
    require_hex64(&raw.retraction_intent_sha256, "retraction_intent_sha256")?;
    if let Some(intent_id) = raw.local_intent_id.as_deref() {
        require_hex64(intent_id, "local_intent_id")?;
    }
    require_hex64(&raw.first_epoch_id, "first_epoch_id")?;
    Ok(FindingStatusLeafRecord {
        feed_id: raw.feed_id,
        operator_id: raw.operator_id,
        finding_id: raw.finding_id,
        key_domain_nonce: nonce,
        status_value_sha256: raw.status_value_sha256,
        status_value_bytes: raw.status_value_bytes,
        retraction_intent_sha256: raw.retraction_intent_sha256,
        local_intent_id: raw.local_intent_id,
        first_map_epoch: stored_u64(raw.first_map_epoch, "first_map_epoch")?,
        first_epoch_id: raw.first_epoch_id,
        recorded_at: stored_u64(raw.recorded_at, "recorded_at")?,
    })
}

pub(super) fn load_leaf_tx(
    transaction: &Transaction<'_>,
    feed_id: &str,
    finding_id: &str,
) -> Result<Option<FindingStatusLeafRecord>, FindingStatusStoreError> {
    let raw = transaction
        .query_row(
            r#"
            SELECT feed_id, operator_id, finding_id, key_domain_nonce,
                   status_value_sha256, status_value_bytes,
                   retraction_intent_sha256, local_intent_id,
                   first_map_epoch, first_epoch_id, recorded_at
            FROM finding_status_leaves
            WHERE feed_id = ?1 AND finding_id = ?2
            "#,
            params![feed_id, finding_id],
            raw_leaf_from_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(leaf_from_raw).transpose()
}

#[derive(Debug)]
pub(super) struct RawProof {
    feed_id: String,
    operator_id: String,
    finding_id: String,
    key_domain_nonce: i64,
    map_epoch: i64,
    epoch_id: String,
    root_hash: String,
    proof_kind: String,
    proof_sha256: String,
    proof_bytes: Vec<u8>,
    status_value_sha256: Option<String>,
    status_value_bytes: Option<Vec<u8>>,
    retraction_intent_sha256: Option<String>,
    checked_at: i64,
    valid_until: i64,
    recorded_at: i64,
    signed_epoch_sha256: String,
    signed_epoch_bytes: Vec<u8>,
}

pub(super) fn raw_proof_from_row(row: &Row<'_>) -> rusqlite::Result<RawProof> {
    Ok(RawProof {
        feed_id: row.get(0)?,
        operator_id: row.get(1)?,
        finding_id: row.get(2)?,
        key_domain_nonce: row.get(3)?,
        map_epoch: row.get(4)?,
        epoch_id: row.get(5)?,
        root_hash: row.get(6)?,
        proof_kind: row.get(7)?,
        proof_sha256: row.get(8)?,
        proof_bytes: row.get(9)?,
        status_value_sha256: row.get(10)?,
        status_value_bytes: row.get(11)?,
        retraction_intent_sha256: row.get(12)?,
        checked_at: row.get(13)?,
        valid_until: row.get(14)?,
        recorded_at: row.get(15)?,
        signed_epoch_sha256: row.get(16)?,
        signed_epoch_bytes: row.get(17)?,
    })
}

pub(super) fn proof_from_raw(
    raw: RawProof,
) -> Result<FindingStatusProofRecord, FindingStatusStoreError> {
    let nonce = stored_u64(raw.key_domain_nonce, "key_domain_nonce")?;
    require_fixed_nonce(nonce)?;
    require_hex64(&raw.finding_id, "finding_id")?;
    require_hex64(&raw.epoch_id, "epoch_id")?;
    require_hex64(&raw.root_hash, "root_hash")?;
    require_hex64(&raw.proof_sha256, "proof_sha256")?;
    require_bytes(
        &raw.proof_bytes,
        MAX_FINDING_STATUS_PROOF_BYTES,
        "proof_bytes",
    )?;
    if sha256_hex(&raw.proof_bytes) != raw.proof_sha256 {
        return Err(invariant("retained proof bytes fail their digest"));
    }
    match (
        raw.status_value_sha256.as_deref(),
        raw.status_value_bytes.as_deref(),
    ) {
        (Some(digest), Some(bytes)) => {
            require_hex64(digest, "status_value_sha256")?;
            require_bytes(bytes, MAX_FINDING_STATUS_VALUE_BYTES, "status_value_bytes")?;
            if sha256_hex(bytes) != digest {
                return Err(invariant("retained proof value fails its digest"));
            }
        }
        (None, None) => {}
        _ => return Err(invariant("retained proof has a partial status value")),
    }
    if let Some(digest) = raw.retraction_intent_sha256.as_deref() {
        require_hex64(digest, "retraction_intent_sha256")?;
    }
    require_hex64(&raw.signed_epoch_sha256, "signed_epoch_sha256")?;
    require_bytes(
        &raw.signed_epoch_bytes,
        MAX_FINDING_STATUS_EPOCH_BYTES,
        "signed_epoch_bytes",
    )?;
    if sha256_hex(&raw.signed_epoch_bytes) != raw.signed_epoch_sha256 {
        return Err(invariant(
            "proof's retained signed epoch bytes fail their digest",
        ));
    }
    let record = FindingStatusProofRecord {
        feed_id: raw.feed_id,
        operator_id: raw.operator_id,
        key_domain_nonce: nonce,
        map_epoch: stored_u64(raw.map_epoch, "map_epoch")?,
        epoch_id: raw.epoch_id,
        root_hash: raw.root_hash,
        finding_id: raw.finding_id,
        kind: proof_kind_from_name(&raw.proof_kind)?,
        proof_sha256: raw.proof_sha256,
        proof_bytes: raw.proof_bytes,
        status_value_sha256: raw.status_value_sha256,
        status_value_bytes: raw.status_value_bytes,
        retraction_intent_sha256: raw.retraction_intent_sha256,
        checked_at: stored_u64(raw.checked_at, "checked_at")?,
        valid_until: stored_u64(raw.valid_until, "valid_until")?,
        recorded_at: stored_u64(raw.recorded_at, "recorded_at")?,
        signed_epoch_sha256: raw.signed_epoch_sha256,
        signed_epoch_bytes: raw.signed_epoch_bytes,
    };
    match record.kind {
        FindingStatusProofKind::Inclusion
            if record.status_value_sha256.is_none()
                || record.status_value_bytes.is_none()
                || record.retraction_intent_sha256.is_none() =>
        {
            Err(invariant("retained inclusion proof lost branch fields"))
        }
        FindingStatusProofKind::NonInclusion
            if record.status_value_sha256.is_some()
                || record.status_value_bytes.is_some()
                || record.retraction_intent_sha256.is_some() =>
        {
            Err(invariant(
                "retained non-inclusion proof has inclusion branch fields",
            ))
        }
        _ => Ok(record),
    }
}

pub(super) const PROOF_SELECT: &str = r#"
    SELECT p.feed_id, p.operator_id, p.finding_id, p.key_domain_nonce,
           p.map_epoch, p.epoch_id, p.root_hash, p.proof_kind,
           p.proof_sha256, p.proof_bytes, p.status_value_sha256,
           p.status_value_bytes, p.retraction_intent_sha256, p.checked_at,
           p.valid_until, p.recorded_at, e.signed_epoch_sha256,
           e.signed_epoch_bytes
    FROM finding_status_proofs p
    JOIN finding_status_epochs e
      ON e.feed_id = p.feed_id AND e.map_epoch = p.map_epoch
"#;

pub(super) fn load_proof_tx(
    transaction: &Transaction<'_>,
    feed_id: &str,
    finding_id: &str,
    map_epoch: u64,
) -> Result<Option<FindingStatusProofRecord>, FindingStatusStoreError> {
    let query =
        format!("{PROOF_SELECT} WHERE p.feed_id = ?1 AND p.finding_id = ?2 AND p.map_epoch = ?3");
    let raw = transaction
        .query_row(
            &query,
            params![feed_id, finding_id, sqlite_i64(map_epoch, "map_epoch")?],
            raw_proof_from_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(proof_from_raw).transpose()
}

pub(super) fn proof_record_matches_input(
    record: &FindingStatusProofRecord,
    input: &VerifiedFindingStatusProofInput<'_>,
    proof_sha256: &str,
    status_value_sha256: Option<&str>,
) -> bool {
    record.feed_id == input.feed_id
        && record.operator_id == input.operator_id
        && record.key_domain_nonce == input.key_domain_nonce
        && record.map_epoch == input.map_epoch
        && record.epoch_id == input.epoch_id
        && record.root_hash == input.root_hash
        && record.finding_id == input.finding_id
        && record.kind == input.kind
        && record.proof_sha256 == proof_sha256
        && record.proof_bytes == input.proof_bytes
        && record.status_value_sha256.as_deref() == status_value_sha256
        && record.status_value_bytes.as_deref() == input.status_value_bytes
        && record.retraction_intent_sha256.as_deref() == input.retraction_intent_sha256
        && record.checked_at == input.checked_at
        && record.valid_until == input.valid_until
}

pub(super) fn verify_proof_record_at_floor(
    proof: &FindingStatusProofRecord,
    floor: &FindingStatusFeedFloor,
) -> Result<(), FindingStatusStoreError> {
    if proof.feed_id != floor.feed_id
        || proof.operator_id != floor.operator_id
        || proof.key_domain_nonce != floor.key_domain_nonce
        || proof.map_epoch != floor.map_epoch
        || proof.epoch_id != floor.epoch_id
        || proof.root_hash != floor.root_hash
        || proof.signed_epoch_sha256 != floor.signed_epoch_sha256
    {
        return Err(invariant(
            "status proof does not match the exact durable current floor",
        ));
    }
    Ok(())
}

pub(super) const fn intent_source_name(source: FindingRetractionIntentSource) -> &'static str {
    match source {
        FindingRetractionIntentSource::Voluntary => "voluntary",
        FindingRetractionIntentSource::Enforcement => "enforcement",
    }
}

pub(super) fn intent_source_from_name(
    name: &str,
) -> Result<FindingRetractionIntentSource, FindingStatusStoreError> {
    match name {
        "voluntary" => Ok(FindingRetractionIntentSource::Voluntary),
        "enforcement" => Ok(FindingRetractionIntentSource::Enforcement),
        other => Err(invariant(format!(
            "unknown retraction intent source {other}"
        ))),
    }
}

pub(super) fn intent_state_from_name(
    name: &str,
) -> Result<FindingRetractionIntentState, FindingStatusStoreError> {
    match name {
        "waiting_finality" => Ok(FindingRetractionIntentState::WaitingFinality),
        "dispatch_eligible" => Ok(FindingRetractionIntentState::DispatchEligible),
        "published" => Ok(FindingRetractionIntentState::Published),
        other => Err(invariant(format!(
            "unknown retraction intent state {other}"
        ))),
    }
}

pub(super) fn sticky_status_from_name(
    name: &str,
) -> Result<FindingStickyStatus, FindingStatusStoreError> {
    match name {
        "pending" => Ok(FindingStickyStatus::Pending),
        "retracted" => Ok(FindingStickyStatus::Retracted),
        other => Err(invariant(format!("unknown sticky finding status {other}"))),
    }
}

pub(super) const fn proof_kind_name(kind: FindingStatusProofKind) -> &'static str {
    match kind {
        FindingStatusProofKind::Inclusion => "inclusion",
        FindingStatusProofKind::NonInclusion => "non_inclusion",
    }
}

pub(super) fn proof_kind_from_name(
    name: &str,
) -> Result<FindingStatusProofKind, FindingStatusStoreError> {
    match name {
        "inclusion" => Ok(FindingStatusProofKind::Inclusion),
        "non_inclusion" => Ok(FindingStatusProofKind::NonInclusion),
        other => Err(invariant(format!(
            "unknown finding status proof kind {other}"
        ))),
    }
}

pub(super) fn require_fixed_nonce(nonce: u64) -> Result<(), FindingStatusStoreError> {
    if nonce != FINDING_STATUS_KEY_DOMAIN_NONCE {
        return Err(invariant(format!(
            "key_domain_nonce must equal fixed finding-status nonce {FINDING_STATUS_KEY_DOMAIN_NONCE}"
        )));
    }
    Ok(())
}

pub(super) fn require_identifier(
    value: &str,
    field: &'static str,
) -> Result<(), FindingStatusStoreError> {
    require_identifier_with_bound(value, 512, field)
}

pub(super) fn require_identifier_with_bound(
    value: &str,
    maximum: usize,
    field: &'static str,
) -> Result<(), FindingStatusStoreError> {
    if value.is_empty() || value.len() > maximum {
        return Err(invariant(format!("{field} byte length is out of bounds")));
    }
    Ok(())
}

pub(super) fn require_hex64(
    value: &str,
    field: &'static str,
) -> Result<(), FindingStatusStoreError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }
    Err(invariant(format!(
        "{field} is not 64 lowercase hex characters"
    )))
}

pub(super) fn require_bytes(
    bytes: &[u8],
    maximum: usize,
    field: &'static str,
) -> Result<(), FindingStatusStoreError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(invariant(format!("{field} byte length is out of bounds")));
    }
    Ok(())
}

pub(super) fn require_positive(
    value: u64,
    field: &'static str,
) -> Result<(), FindingStatusStoreError> {
    if value == 0 {
        return Err(invariant(format!("{field} must be positive")));
    }
    sqlite_i64(value, field).map(|_| ())
}

pub(super) fn sqlite_i64(value: u64, field: &'static str) -> Result<i64, FindingStatusStoreError> {
    i64::try_from(value).map_err(|_| invariant(format!("{field} exceeds SQLite integer range")))
}

pub(super) fn stored_u64(value: i64, field: &'static str) -> Result<u64, FindingStatusStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("{field} is negative")))
}

pub(super) fn stored_optional_u64(
    value: Option<i64>,
    field: &'static str,
) -> Result<Option<u64>, FindingStatusStoreError> {
    value.map(|value| stored_u64(value, field)).transpose()
}

pub(super) fn invariant(detail: impl Into<String>) -> FindingStatusStoreError {
    FindingStatusStoreError::Invariant(detail.into())
}

pub(super) fn admission_error(error: AdmissionOperationStoreError) -> FindingStatusStoreError {
    match error {
        AdmissionOperationStoreError::Fenced => FindingStatusStoreError::Fenced,
        AdmissionOperationStoreError::NotFound => {
            FindingStatusStoreError::Unavailable("serving-owner state not found".to_owned())
        }
        AdmissionOperationStoreError::Unavailable(detail) => {
            FindingStatusStoreError::Unavailable(detail)
        }
        AdmissionOperationStoreError::OutcomeUnknown(detail) => {
            FindingStatusStoreError::OutcomeUnknown(detail)
        }
        AdmissionOperationStoreError::Invariant(detail) => {
            FindingStatusStoreError::Invariant(detail)
        }
        AdmissionOperationStoreError::Operation(error) => invariant(error.to_string()),
    }
}

pub(super) fn sqlite_error(error: rusqlite::Error) -> FindingStatusStoreError {
    match &error {
        rusqlite::Error::SqliteFailure(code, _)
            if matches!(
                code.code,
                ErrorCode::ConstraintViolation
                    | ErrorCode::DatabaseBusy
                    | ErrorCode::DatabaseLocked
            ) =>
        {
            if code.code == ErrorCode::ConstraintViolation {
                FindingStatusStoreError::Conflict(error.to_string())
            } else {
                FindingStatusStoreError::Unavailable(error.to_string())
            }
        }
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::Utf8Error(..) => invariant(error.to_string()),
        _ => FindingStatusStoreError::Unavailable(error.to_string()),
    }
}
