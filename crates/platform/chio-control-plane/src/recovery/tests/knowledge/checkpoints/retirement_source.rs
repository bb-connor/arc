//! Direct legacy retirement keeps the original cold source through suffix collisions.
use super::*;

mod fixture;
use fixture::*;

fn checkpoint_owner(f: &KnowledgeFixture, id: &str) -> TestResult<serde_json::Value> {
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let payload: Vec<u8> = connection.query_row(
        "SELECT payload FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-reference-owner:*'
           AND json_extract(payload,'$.owner.owner')='checkpoint_revision'
           AND json_extract(payload,'$.owner.checkpoint')=?1
           AND json_extract(payload,'$.owner.revision')=1",
        [id],
        |row| row.get(0),
    )?;
    Ok(serde_json::from_slice(&payload)?)
}

fn assert_current_source(f: &KnowledgeFixture, original: &LegacyCheckpoint) -> TestResult {
    let store = f.f.authority.admission_operation_store();
    let read = store.read_labeled_checkpoint(
        &f.actor(RecoveryPermission::KnowledgeRead)?,
        &original.checkpoint.checkpoint,
        1,
        &f.f.authority.mutation_fence(),
        now_ms()?,
    )?;
    assert_eq!(read, original.checkpoint);
    assert_eq!(
        store.read_labeled_checkpoint(
            &f.actor(RecoveryPermission::KnowledgeRead)?,
            &original.checkpoint.checkpoint,
            0,
            &f.f.authority.mutation_fence(),
            now_ms()?,
        )?,
        original.checkpoint
    );
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let aliases: i64 = connection.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-checkpoint:v2:*'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        aliases, 0,
        "current reads must preserve the original legacy source"
    );
    let (version, payload, digest, event_sequence): (i64, Vec<u8>, String, i64) = connection
        .query_row(
            "SELECT r.version,r.payload,e.record_digest,e.sequence
         FROM admission_operation_recovery_records r
         JOIN admission_operation_recovery_events e
           ON e.record_key=r.record_key AND e.record_version=r.version
         WHERE r.record_key=?1",
            [&original.key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
    assert_eq!(version, 1);
    assert_eq!(
        payload,
        chio_core_types::canonical_json_bytes(&original.checkpoint)?
    );
    let owner = checkpoint_owner(f, original.checkpoint.checkpoint.as_str())?;
    assert_eq!(owner["state"], "active");
    assert_eq!(owner["original"]["record_key"], original.key);
    assert_eq!(owner["original"]["version"], version);
    assert_eq!(
        owner["original"]["digest"],
        serde_json::to_value(hex::decode(digest)?)?
    );
    assert_eq!(owner["original"]["event_sequence"], event_sequence);
    assert_eq!(owner["original"]["kind"], "command");
    assert_eq!(
        owner["original"]["scope_key"],
        chio_core_types::sha256_hex(&chio_core_types::canonical_json_bytes(
            &original.checkpoint.scope
        )?)
    );
    let global: i64 = connection.query_row(
        "SELECT commit_sequence FROM authority_global_commits
         WHERE projection_kind='recovery' AND projection_key=?1 AND projection_sequence=?2",
        rusqlite::params![&original.key, version],
        |row| row.get(0),
    )?;
    assert_eq!(owner["original"]["global_commit_sequence"], global);
    Ok(())
}

#[derive(Debug, PartialEq)]
struct RetainedState {
    records: Vec<(String, i64, Vec<u8>)>,
    events: i64,
    commits: i64,
}

fn rows(f: &KnowledgeFixture, pattern: &str) -> TestResult<Vec<(String, i64, Vec<u8>)>> {
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let mut query = connection.prepare(
        "SELECT record_key,version,payload FROM admission_operation_recovery_records
         WHERE record_key GLOB ?1 ORDER BY record_key",
    )?;
    let rows = query
        .query_map([pattern], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<_, _>>()?;
    Ok(rows)
}

fn retained_state(f: &KnowledgeFixture) -> TestResult<RetainedState> {
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    Ok(RetainedState {
        records: rows(f, "*")?,
        events: connection.query_row(
            "SELECT count(*) FROM admission_operation_recovery_events",
            [],
            |row| row.get(0),
        )?,
        commits: connection.query_row(
            "SELECT count(*) FROM authority_global_commits",
            [],
            |row| row.get(0),
        )?,
    })
}

fn retire(f: &KnowledgeFixture, original: &LegacyCheckpoint) -> TestResult {
    f.f.authority
        .admission_operation_store()
        .retire_checkpoint_revision(
            &f.actor(RecoveryPermission::KnowledgeAdmin)?,
            &original.checkpoint.checkpoint,
            1,
            &f.f.authority.mutation_fence(),
            now_ms()?,
        )?;
    Ok(())
}

fn assert_retired_restore_refused(f: &KnowledgeFixture, original: &LegacyCheckpoint) -> TestResult {
    let sink = f.sink();
    for revision in [0, 1] {
        assert!(f
            .runtime
            .restore_into(
                &f.f.control,
                &original.checkpoint.checkpoint,
                revision,
                &RequestId::new("retired-legacy-refusal")?,
                &sink,
            )
            .is_err());
    }
    assert!(sink.delivered.lock().map_err(|_| "sink")?.is_empty());
    Ok(())
}

#[test]
fn memory_legacy_revision_retirement_uses_its_exact_owning_source_when_revision_slot_is_foreign(
) -> TestResult {
    let ColdRetirementFixture {
        mut knowledge,
        own,
        foreign,
    } = ColdRetirementFixture::new()?;
    assert_current_source(&knowledge, &own)?;
    assert_current_source(&knowledge, &foreign)?;
    let ready = rows(&knowledge, "knowledge-reference-ready:*")?;
    assert_eq!(ready.len(), 1);
    let marker: serde_json::Value = serde_json::from_slice(&ready[0].2)?;
    assert_eq!(marker["artifact_count"], 2);
    assert_eq!(marker["active_owner_count"], 2);
    let originals = rows(&knowledge, "knowledge-checkpoint:*")?;
    for (original, bytes) in [
        (&own, b"own-legacy".as_slice()),
        (&foreign, b"foreign-legacy".as_slice()),
    ] {
        assert_eq!(knowledge.broker.read_private(&original.seal)?, bytes);
        let sink = knowledge.sink();
        knowledge.runtime.restore_into(
            &knowledge.f.control,
            &original.checkpoint.checkpoint,
            1,
            &RequestId::new(original.checkpoint.checkpoint.as_str())?,
            &sink,
        )?;
        assert_restored_checkpoint(&sink, original.checkpoint.checkpoint.as_str(), 1, bytes)?;
        assert!(knowledge
            .runtime
            .collect(&knowledge.f.control, original.reference())
            .is_err());
    }
    assert_current_source(&knowledge, &own)?;
    let foreign_before = checkpoint_owner(&knowledge, "job:1")?;
    let before = retained_state(&knowledge)?;
    let retired = retire(&knowledge, &own);
    if retired.is_err() {
        assert_eq!(
            retained_state(&knowledge)?,
            before,
            "a refused retirement must roll back its terminal, owners and counters"
        );
    }
    assert!(
        retired.is_ok(),
        "authentic own legacy source must retire despite a foreign revision slot: {retired:?}"
    );
    retired?;
    assert_eq!(checkpoint_owner(&knowledge, "job")?["state"], "retired");
    assert_eq!(checkpoint_owner(&knowledge, "job:1")?, foreign_before);
    let after = retained_state(&knowledge)?;
    retire(&knowledge, &own)?;
    retire(&knowledge, &own)?;
    assert_eq!(
        retained_state(&knowledge)?,
        after,
        "replay cannot decrement or allocate twice"
    );
    assert_retired_restore_refused(&knowledge, &own)?;
    knowledge
        .runtime
        .collect(&knowledge.f.control, own.reference())?;
    assert!(knowledge.broker.read_private(&own.seal).is_err());
    assert_eq!(
        knowledge.broker.read_private(&foreign.seal)?,
        b"foreign-legacy"
    );
    assert!(knowledge
        .runtime
        .collect(&knowledge.f.control, foreign.reference())
        .is_err());
    assert_eq!(rows(&knowledge, "knowledge-checkpoint:*")?, originals);
    assert_eq!(rows(&knowledge, "knowledge-reference-ready:*")?, ready);

    let path = knowledge.f.path.clone();
    let directory = knowledge.f._directory.take();
    drop(knowledge);
    let knowledge = KnowledgeFixture::from(RecoveryFixture::open(path, directory, false)?)?;
    assert_eq!(
        rows(&knowledge, "knowledge-reference-ready:*")?,
        ready,
        "reopen must not reset the cold census"
    );
    let reopened = retained_state(&knowledge)?;
    retire(&knowledge, &own)?;
    assert_eq!(retained_state(&knowledge)?, reopened);
    assert_retired_restore_refused(&knowledge, &own)?;
    assert_current_source(&knowledge, &foreign)?;
    let sink = knowledge.sink();
    knowledge.runtime.restore_into(
        &knowledge.f.control,
        &foreign.checkpoint.checkpoint,
        0,
        &RequestId::new("foreign-after-reopen")?,
        &sink,
    )?;
    assert_restored_checkpoint(&sink, "job:1", 1, b"foreign-legacy")?;
    assert!(knowledge
        .runtime
        .collect(&knowledge.f.control, foreign.reference())
        .is_err());
    assert_eq!(checkpoint_owner(&knowledge, "job:1")?, foreign_before);
    assert_eq!(rows(&knowledge, "knowledge-checkpoint:*")?, originals);
    let replacement = knowledge.publish("successor", b"successor-bytes")?;
    assert!(knowledge
        .runtime
        .checkpoint(
            &knowledge.f.control,
            &own.checkpoint.checkpoint,
            0,
            std::slice::from_ref(&replacement),
            &[]
        )
        .is_err());
    let next = knowledge.runtime.checkpoint(
        &knowledge.f.control,
        &own.checkpoint.checkpoint,
        1,
        std::slice::from_ref(&replacement),
        &[],
    )?;
    assert_eq!(
        next.revision.get(),
        2,
        "retirement must not reset consumed revision identity"
    );
    assert_eq!(checkpoint_owner(&knowledge, "job")?["state"], "retired");
    assert_eq!(rows(&knowledge, "knowledge-reference-ready:*")?, ready);
    Ok(())
}

#[test]
fn memory_legacy_revision_retirement_rolls_back_after_its_original_owner_write_fault() -> TestResult
{
    let mut f = ColdRetirementFixture::new()?;
    assert_current_source(&f.knowledge, &f.own)?;
    assert_current_source(&f.knowledge, &f.foreign)?;
    let fault = RetirementWriteFault::install(&f.knowledge)?;
    let before = retained_state(&f.knowledge)?;
    let error = retire(&f.knowledge, &f.own)
        .err()
        .ok_or("retirement must hit owner write fault")?;
    assert_eq!(retained_state(&f.knowledge)?, before);
    fault.clear()?;
    assert!(
        error
            .to_string()
            .contains("injected checkpoint owner retirement failure"),
        "must reach the intended owner write after staging its terminal: {error}"
    );
    assert_current_source(&f.knowledge, &f.own)?;
    assert_current_source(&f.knowledge, &f.foreign)?;
    let sink = f.knowledge.sink();
    f.knowledge.runtime.restore_into(
        &f.knowledge.f.control,
        &f.own.checkpoint.checkpoint,
        1,
        &RequestId::new("rollback-live")?,
        &sink,
    )?;
    assert_restored_checkpoint(&sink, "job", 1, b"own-legacy")?;
    retire(&f.knowledge, &f.own)?;
    f.knowledge
        .runtime
        .collect(&f.knowledge.f.control, f.own.reference())?;
    assert!(f.knowledge.broker.read_private(&f.own.seal).is_err());
    assert_eq!(
        f.knowledge.broker.read_private(&f.foreign.seal)?,
        b"foreign-legacy"
    );
    let path = f.knowledge.f.path.clone();
    let directory = f.knowledge.f._directory.take();
    let own = f.own;
    let foreign = f.foreign;
    drop(f.knowledge);
    let reopened = KnowledgeFixture::from(RecoveryFixture::open(path, directory, false)?)?;
    retire(&reopened, &own)?;
    assert_retired_restore_refused(&reopened, &own)?;
    assert_current_source(&reopened, &foreign)?;
    assert!(reopened
        .runtime
        .collect(&reopened.f.control, foreign.reference())
        .is_err());

    Ok(())
}
