//! The native knowledge journal seals its 4,097th live join and continues. The
//! seal and the join it precedes commit or roll back together, a replay writes
//! no history, the original capability reopens the store, and a damaged seal
//! refuses the reopened store.
use super::*;

/// Knowledge join roots one live journal segment holds.
const LIVE_JOINS: usize = 4096;
const SEAL_KEYS: &str = "native-journal-seal:*";

/// Seal records, seal events, seal global commits and knowledge join roots.
fn journal(database: &std::path::Path) -> TestResult<[i64; 4]> {
    let connection = rusqlite::Connection::open(database)?;
    Ok(connection.query_row(
        "SELECT (SELECT COUNT(*) FROM admission_operation_recovery_records WHERE record_key GLOB ?1),
                (SELECT COUNT(*) FROM admission_operation_recovery_events WHERE record_key GLOB ?1),
                (SELECT COUNT(*) FROM authority_global_commits
                 WHERE projection_kind = 'recovery' AND projection_key GLOB ?1),
                (SELECT COUNT(*) FROM admission_operation_recovery_records
                 WHERE record_key GLOB 'knowledge-join:*')",
        [SEAL_KEYS],
        |row| Ok([row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?]),
    )?)
}

/// Apply one statement to the closed authority with the recovery record guards
/// lifted and then restored exactly.
fn damage(database: &std::path::Path, statement: &str) -> TestResult {
    let connection = rusqlite::Connection::open(database)?;
    connection.pragma_update(None, "foreign_keys", false)?;
    let guards: Vec<(String, String)> = {
        let mut query = connection.prepare(
            "SELECT name, sql FROM sqlite_schema WHERE type = 'trigger'
             AND tbl_name = 'admission_operation_recovery_records' ORDER BY name",
        )?;
        let rows = query.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    for (name, _) in &guards {
        connection.execute_batch(&format!("DROP TRIGGER \"{name}\""))?;
    }
    let changed = connection.execute(statement, [])?;
    for (_, sql) in &guards {
        connection.execute_batch(sql)?;
    }
    if changed != 1 {
        return Err(format!("damage changed {changed} rows: {statement}").into());
    }
    Ok(())
}

fn release(
    f: &KnowledgeFixture,
    capability: &CapabilityToken,
    handle: &ArtifactHandleV1,
    request: &str,
) -> TestResult<ArtifactDeliveryOutcomeV1> {
    Ok(f.runtime.release_into(
        capability,
        &RequestId::new(request)?,
        f.runtime.prepare_read(capability, handle)?,
        &f.sink(),
    )?)
}

/// Whether reopening the closed authority, or its first new release, refuses.
fn reopen_refuses(directory: &std::path::Path, handle: &ArtifactHandleV1) -> bool {
    let attempt = || -> TestResult {
        let f =
            KnowledgeFixture::from(RecoveryFixture::open(directory.to_path_buf(), None, false)?)?;
        release(&f, &f.f.control, handle, "after-damage")?;
        Ok(())
    };
    attempt().is_err()
}

#[test]
fn knowledge_journal_seals_its_4097th_join_and_continues() -> TestResult {
    // 4,097 real joins outlive the fixture's 600-second process seed
    // capability, while Knowledge control spans 1,200 seconds. Freeze the
    // shared thread-bound fixture clock so the joins, restart and tamper
    // checks measure seal integrity, not wall-clock capability expiry.
    let _clock = scope_synchronous_fixture_clock(now_ms()? / 1_000);
    let mut f = KnowledgeFixture::new()?;
    let directory = f.f.path.clone();
    let database = directory.join("admission.db");
    let reference = publish_label(
        &f,
        "segment-artifact",
        b"segment-artifact",
        InformationLabel::bottom(),
    )?;
    let handle = f.runtime.handle(
        &f.f.control,
        &reference,
        &ArtifactRecipientId::new("agent-root")?,
    )?;
    let original = f.f.control.clone();
    let first = release(&f, &original, &handle, "segment-0")?;
    for index in 1..LIVE_JOINS {
        release(&f, &original, &handle, &format!("segment-{index}"))?;
    }
    let live = i64::try_from(LIVE_JOINS)?;
    assert_eq!(journal(&database)?, [0, 0, 0, live]);

    // The next join must seal first. A fault after the seal persisted rolls
    // back the seal, its event, its global commit and the join together.
    let fault =
        f.f.authority
            .admission_operation_store()
            .inject_native_journal_seal_fault_fixture(&f.profile.native_authority)?;
    assert!(release(&f, &original, &handle, "segment-crossing").is_err());
    drop(fault);
    assert_eq!(journal(&database)?, [0, 0, 0, live]);
    release(&f, &original, &handle, "segment-crossing")?;
    assert_eq!(journal(&database)?, [1, 1, 1, live + 1]);
    release(&f, &original, &handle, "segment-continued")?;
    assert_eq!(journal(&database)?, [1, 1, 1, live + 2]);

    // A release from the sealed segment replays exactly and writes no journal.
    let before = journal(&database)?;
    assert_eq!(
        release(&f, &original, &handle, "segment-0")?.release,
        first.release
    );
    assert_eq!(journal(&database)?, before);

    // The store reopens: the original capability replays its sealed release
    // exactly, and the reopened journal continues.
    let temporary = f.f._directory.take();
    drop(f);
    let g = KnowledgeFixture::from(RecoveryFixture::open(directory.clone(), None, false)?)?;
    assert_eq!(
        release(&g, &original, &handle, "segment-0")?.release,
        first.release
    );
    assert_eq!(journal(&database)?, [1, 1, 1, live + 2]);
    release(&g, &g.f.control, &handle, "after-reopen")?;
    assert_eq!(journal(&database)?, [1, 1, 1, live + 3]);
    drop(g);

    // Tampered, missing, orphan and gapped seals each refuse the reopened store.
    let (key, scope, payload): (String, String, String) = rusqlite::Connection::open(&database)?
        .query_row(
            "SELECT record_key, scope_key, hex(payload) FROM admission_operation_recovery_records
             WHERE record_key GLOB ?1",
            [SEAL_KEYS],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
    let gap = format!(
        "{}{:016}",
        key.strip_suffix(&format!("{:016}", 0))
            .ok_or("the first seal is not segment zero")?,
        1
    );
    let orphan = format!("native-journal-seal:{}:{:016}", "0".repeat(64), 0);
    let row = |record_key: &str| {
        format!(
            "INSERT INTO admission_operation_recovery_records
             (record_key, scope_key, kind, version, payload, native_namespace, native_request)
             VALUES ('{record_key}', '{scope}', 'command', 1, X'{payload}', NULL, NULL)"
        )
    };
    let records = "UPDATE admission_operation_recovery_records";
    for (damaged, repair) in [
        (
            format!("{records} SET payload = X'{payload}20' WHERE record_key = '{key}'"),
            format!("{records} SET payload = X'{payload}' WHERE record_key = '{key}'"),
        ),
        (
            format!("DELETE FROM admission_operation_recovery_records WHERE record_key = '{key}'"),
            row(&key),
        ),
        (
            row(&orphan),
            format!(
                "DELETE FROM admission_operation_recovery_records WHERE record_key = '{orphan}'"
            ),
        ),
        (
            format!("{records} SET record_key = '{gap}' WHERE record_key = '{key}'"),
            format!("{records} SET record_key = '{key}' WHERE record_key = '{gap}'"),
        ),
    ] {
        damage(&database, &damaged)?;
        assert!(reopen_refuses(&directory, &handle), "{damaged}");
        damage(&database, &repair)?;
    }
    // The repaired store reopens, so each refusal came from its damage.
    assert!(!reopen_refuses(&directory, &handle));
    drop(temporary);
    Ok(())
}
