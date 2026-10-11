//! Retained checkpoint rows grow with row changes, not with sealed segments.
use super::*;
use chio_kernel::SecurityInvocationContextV1;
use chio_security_types::ports::LineageId;
use std::collections::BTreeSet;

/// Join under a lineage no earlier call used. Lineage labels are never
/// compacted, so every call grows the live image by at least one row.
fn join_new_lineage(
    fixture: &Fixture,
    initialized: &SecurityParticipantStateInitialization,
    name: &str,
) -> AnchoredTestResult<AdmissionOperationId> {
    let (base, mut request) = mutations::request(&format!("{name}-join"))?;
    let base = base.as_v1();
    request.key.lineage_id = LineageId::new(name)?;
    let context = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        base.tenant_id().clone(),
        base.session_id().clone(),
        base.principal_id().clone(),
        base.isolation_epoch_id().clone(),
        request.key.lineage_id.clone(),
        1,
    ));
    let (operation, lease) = mutations::setup(fixture, name, &context)?;
    fixture.store.join_security_participant_flow(
        &operation,
        &lease,
        initialized,
        &context,
        &request,
        now_ms(),
    )?;
    Ok(operation.binding().operation_id().clone())
}

/// Current native rows of the participant as (table, rendered values).
fn image(
    fixture: &Fixture,
    initialized: &SecurityParticipantStateInitialization,
) -> AnchoredTestResult<BTreeSet<(String, String)>> {
    let connection = fixture.store.connection()?;
    let mut rows = BTreeSet::new();
    for table in native::schema::TABLES {
        let mut statement = connection.prepare(&format!(
            "SELECT * FROM {} WHERE security_authority_id = ?1",
            table.native
        ))?;
        let columns = statement.column_count();
        let mut selected = statement.query([initialized.security_authority_id().as_str()])?;
        while let Some(row) = selected.next()? {
            let values = (0..columns)
                .map(|index| row.get_ref(index).map(|value| format!("{value:?}")))
                .collect::<rusqlite::Result<Vec<_>>>()?;
            if !rows.insert((table.native.to_owned(), values.join("|"))) {
                return Err("current native image repeats a row".into());
            }
        }
    }
    Ok(rows)
}

fn retained_rows(fixture: &Fixture) -> AnchoredTestResult<u64> {
    let stored: i64 = fixture.store.connection()?.query_row(
        "SELECT COUNT(*) FROM security_participant_checkpoint_rows",
        [],
        |row| row.get(0),
    )?;
    Ok(u64::try_from(stored)?)
}

/// Every sealed record in sequence order, decoded from its canonical bytes.
fn records(fixture: &Fixture) -> AnchoredTestResult<Vec<serde_json::Value>> {
    let connection = fixture.store.connection()?;
    let mut statement = connection.prepare(
        "SELECT canonical_record FROM security_participant_checkpoint_events ORDER BY sequence",
    )?;
    let records = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    records
        .iter()
        .map(|bytes| Ok(serde_json::from_slice(bytes)?))
        .collect()
}

/// Stored rows a fold of the latest seal reads: its keyframe and every delta
/// since.
fn fold_rows(fixture: &Fixture, latest: &serde_json::Value) -> AnchoredTestResult<u64> {
    let sequence = latest["sequence"].as_i64().ok_or("latest sequence")?;
    let base = latest["delta"]["base"].as_i64().unwrap_or(sequence);
    let stored: i64 = fixture.store.connection()?.query_row(
        "SELECT COUNT(*) FROM security_participant_checkpoint_rows
         WHERE checkpoint_sequence BETWEEN ?1 AND ?2",
        [base, sequence],
        |row| row.get(0),
    )?;
    Ok(u64::try_from(stored)?)
}

fn seal(
    fixture: &Fixture,
    initialized: &SecurityParticipantStateInitialization,
) -> AnchoredTestResult {
    fixture
        .store
        .checkpoint_security_participant_history(initialized, &fixture.fence, now_ms())?;
    Ok(())
}

/// Seal a keyframe and then deltas until the latest seal is a delta that
/// stores added rows.
fn sealed_delta(
    fixture: &Fixture,
    initialized: &SecurityParticipantStateInitialization,
) -> AnchoredTestResult<serde_json::Value> {
    for index in 0..8 {
        join_new_lineage(fixture, initialized, &format!("sealed-delta-{index}"))?;
        seal(fixture, initialized)?;
        let latest = records(fixture)?.pop().ok_or("no seal")?;
        if latest["delta"]["added_rows"]
            .as_u64()
            .is_some_and(|rows| rows > 0)
        {
            return Ok(latest);
        }
    }
    Err("no delta seal stored added rows".into())
}

fn refused_after(
    fixture: &Fixture,
    initialized: &SecurityParticipantStateInitialization,
    tamper: &str,
) -> AnchoredTestResult {
    {
        let connection = fixture.store.connection()?;
        connection.execute_batch(tamper)?;
        connection.execute_batch(native::checkpoint::sql())?;
    }
    assert!(matches!(
        fixture.store.load_security_participant_state(
            initialized.security_authority_id(),
            &fixture.fence,
            now_ms()
        ),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    Ok(())
}

#[test]
fn native_checkpoint_retained_rows_stay_linear_in_row_changes() -> AnchoredTestResult {
    const CALLS: usize = 24;
    let _clock = chio_test_support::clock::scope_unix_secs(now_ms().div_ceil(1_000));
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let mut previous: Option<BTreeSet<(String, String)>> = None;
    let mut first = 0_u64;
    let mut changes = 0_u64;
    for index in 0..CALLS {
        join_new_lineage(&fixture, &initialized, &format!("delta-lineage-{index:02}"))?;
        seal(&fixture, &initialized)?;
        let current = image(&fixture, &initialized)?;
        let rows = u64::try_from(current.len())?;
        match &previous {
            None => first = rows,
            Some(previous) => {
                assert!(current.len() > previous.len(), "live image did not grow");
                changes = changes
                    .checked_add(u64::try_from(
                        current.symmetric_difference(previous).count(),
                    )?)
                    .ok_or("change count overflow")?;
            }
        }
        // A fold reads its keyframe and changed rows within twice its image.
        let latest = records(&fixture)?.pop().ok_or("no seal")?;
        let read = fold_rows(&fixture, &latest)?;
        assert!(
            read <= rows.max(1).saturating_mul(2),
            "call {index} fold reads {read} rows for a {rows}-row image"
        );
        previous = Some(current);
    }
    let retained = retained_rows(&fixture)?;
    let bound = changes
        .checked_mul(2)
        .and_then(|rows| rows.checked_add(first))
        .ok_or("bound overflow")?;
    assert!(
        retained <= bound,
        "{CALLS} checkpoints retained {retained} rows for {changes} row changes \
         over a {first}-row first image (bound {bound})"
    );
    let sealed = records(&fixture)?;
    let keyframes = sealed
        .iter()
        .filter(|record| record["delta"].is_null())
        .count();
    assert!(
        keyframes < CALLS / 2,
        "{keyframes} of {CALLS} seals recopied the image"
    );
    assert!(
        sealed.iter().any(|record| record["delta"]["removed"]
            .as_array()
            .is_some_and(|removed| !removed.is_empty())),
        "no delta authenticated a removal"
    );
    // Reopen folds the whole archive forward and the live image still matches.
    let fixture = super::reopen(fixture)?;
    fixture
        .store
        .load_security_participant_state(
            initialized.security_authority_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("participant disappeared")?;
    Ok(())
}

#[test]
fn native_checkpoint_delta_refuses_missing_duplicate_or_reordered_records() -> AnchoredTestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(now_ms().div_ceil(1_000));
    for tamper in [
        // A stored added row is missing.
        "DROP TRIGGER security_participant_checkpoint_rows_no_delete;
         DELETE FROM security_participant_checkpoint_rows WHERE rowid = (SELECT MAX(rowid) FROM security_participant_checkpoint_rows);",
        // A stored added row is duplicated under the next index.
        "INSERT INTO security_participant_checkpoint_rows
         SELECT security_authority_id, checkpoint_sequence, table_name, row_index + 1, canonical_row
         FROM security_participant_checkpoint_rows WHERE rowid = (SELECT MAX(rowid) FROM security_participant_checkpoint_rows);",
        // The two latest sealed records trade places.
        "DROP TRIGGER security_participant_checkpoint_events_no_update;
         UPDATE security_participant_checkpoint_events SET canonical_record = CASE sequence
             WHEN (SELECT MAX(sequence) FROM security_participant_checkpoint_events)
             THEN (SELECT canonical_record FROM security_participant_checkpoint_events WHERE sequence = (SELECT MAX(sequence) - 1 FROM security_participant_checkpoint_events))
             ELSE (SELECT canonical_record FROM security_participant_checkpoint_events WHERE sequence = (SELECT MAX(sequence) FROM security_participant_checkpoint_events)) END
         WHERE sequence >= (SELECT MAX(sequence) - 1 FROM security_participant_checkpoint_events);",
    ] {
        let fixture = fixture();
        let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
        sealed_delta(&fixture, &initialized)?;
        refused_after(&fixture, &initialized, tamper)?;
    }
    Ok(())
}

#[test]
fn native_checkpoint_delta_seal_is_atomic_and_survives_reopen() -> AnchoredTestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(now_ms().div_ceil(1_000));
    let _reset = ResetCutpoint;
    for stage in 70..=72 {
        let fixture = fixture();
        let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
        sealed_delta(&fixture, &initialized)?;
        let sealed = records(&fixture)?.len();
        let retained = retained_rows(&fixture)?;
        join_new_lineage(&fixture, &initialized, "atomic-delta")?;
        FAIL_AFTER.set(stage);
        assert!(fixture
            .store
            .checkpoint_security_participant_history(&initialized, &fixture.fence, now_ms())
            .is_err());
        FAIL_AFTER.set(0);
        assert_eq!(records(&fixture)?.len(), sealed);
        assert_eq!(retained_rows(&fixture)?, retained);
        let fixture = super::reopen(fixture)?;
        seal(&fixture, &initialized)?;
        let fixture = super::reopen(fixture)?;
        fixture
            .store
            .load_security_participant_state(
                initialized.security_authority_id(),
                &fixture.fence,
                now_ms(),
            )?
            .ok_or("participant disappeared")?;
    }
    Ok(())
}

/// Keyframes keep the v1 record and the previous writer's row order, which
/// is not digest order. Deltas fold onto such a keyframe unchanged.
#[test]
fn native_checkpoint_delta_folds_onto_a_v1_keyframe() -> AnchoredTestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(now_ms().div_ceil(1_000));
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    join_new_lineage(&fixture, &initialized, "legacy-keyframe")?;
    seal(&fixture, &initialized)?;
    let keyframe = records(&fixture)?.pop().ok_or("no keyframe")?;
    assert_eq!(keyframe["schema"], "chio.native-security-checkpoint.v1");
    assert!(keyframe.get("delta").is_none());
    let stored = {
        let connection = fixture.store.connection()?;
        let mut statement = connection.prepare(
            "SELECT table_name, canonical_row FROM security_participant_checkpoint_rows
             WHERE checkpoint_sequence = 1 ORDER BY table_name, row_index",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    let digest = |row: &[u8]| hex::encode(<sha2::Sha256 as sha2::Digest>::digest(row));
    assert!(
        stored
            .windows(2)
            .any(|pair| pair[0].0 == pair[1].0 && digest(&pair[0].1) > digest(&pair[1].1)),
        "control keyframe is already in digest order"
    );
    let latest = sealed_delta(&fixture, &initialized)?;
    assert_eq!(latest["schema"], "chio.native-security-checkpoint.v2");
    assert_eq!(latest["delta"]["base"], 1);
    let fixture = super::reopen(fixture)?;
    fixture
        .store
        .load_security_participant_state(
            initialized.security_authority_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("participant disappeared")?;
    Ok(())
}
