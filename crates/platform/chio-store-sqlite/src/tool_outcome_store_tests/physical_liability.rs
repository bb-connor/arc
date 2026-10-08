use super::*;
use crate::admission_operation_store::raw_liability_test_support::{
    main_wal_frontier, seven_metadata_command_wal_price, whole_raw_custody_wal_price_before_write,
};

#[test]
fn raw_custody_price_includes_the_blob_claim_and_participant_journals(
) -> Result<(), Box<dyn std::error::Error>> {
    // This exercises the real owning SQLite Raw producer with an ordinary
    // stored operation. It is not a native capture, external tool effect,
    // prepayment loan or financed native acceptance proof.
    let fixture = fixture();
    let begun_at = now_ms();
    let operation = committed(&fixture, "raw-physical-price", begun_at);
    let at = begun_at + 20;
    let value = serde_json::json!({"retained": "r".repeat(32 * 1024 * 1024)});
    let (blob, outcome) = returned_value(&operation, fixture.fence.clone(), at, value, None)?;
    assert!(blob.bytes().len() > 32 * 1024 * 1024);
    assert!(blob.bytes().len() < chio_kernel::tool_outcome::MAX_RAW_INVOCATION_OUTCOME_BYTES);

    // Only the read-only pricing observer uses the command pricer's no-spill
    // profile. The actual owning writer retains its original configuration.
    let observer = Connection::open_with_flags(
        &fixture.database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    observer.pragma_update(None, "cache_spill", false)?;
    let metadata = seven_metadata_command_wal_price(&observer)?;
    assert!(metadata > 0 && metadata < 32 * 1024 * 1024);
    let (writer_spill, writer_mode): (i64, String) = {
        let writer = fixture.outcomes.connection()?;
        (
            writer.query_row("PRAGMA main.cache_spill", [], |row| row.get(0))?,
            writer.query_row("PRAGMA main.journal_mode", [], |row| row.get(0))?,
        )
    };
    assert_eq!(writer_mode, "wal");
    let claimant = id("claimant_id", "tool-outcome-worker");
    let claim = RecoveryClaimRequest {
        operation_id: operation.binding().operation_id(),
        expected_version: operation.version(),
        claimant_id: &claimant,
        expires_at_unix_ms: at + 60_000,
        fence: &fixture.fence,
    };
    // Retain the default-refusing preview from the correct physical prewrite
    // cut. A missing whole price must not hide the actual producer controls.
    let whole_price = whole_raw_custody_wal_price_before_write(
        &fixture.operations,
        &operation,
        &blob,
        &outcome,
        &claim,
        at + 1,
    );
    let before = observed_rows(&observer, operation.binding().operation_id().as_str())?;
    let anchor = fixture.authority.anchor_generation()?;
    let reader = Connection::open_with_flags(
        &fixture.database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    reader.execute_batch("BEGIN")?;
    let _: i64 = reader.query_row(
        "SELECT count(*) FROM main.admission_operations",
        [],
        |row| row.get(0),
    )?;
    let wal_before = main_wal_frontier(&observer)?;
    assert!(
        wal_before.0 > wal_before.1,
        "the reader pins live WAL frames"
    );
    let salts_before = wal_salts(&fixture.database)?;
    let pressure_before = (wal_before.0 - wal_before.1)
        .checked_mul(wal_before.2)
        .and_then(|bytes| bytes.checked_add(32))
        .ok_or("prewrite Raw WAL pressure overflowed")?;
    let admission: &dyn QualifiedAdmissionOperationStore = &fixture.operations;
    let inserted = fixture.outcomes.claim_and_record_tool_returned(
        admission,
        claim,
        &mut qualified_lease(claim, at + 1),
        &operation,
        &blob,
        &outcome,
        &fixture.fence,
        at + 1,
    )?;
    assert!(matches!(
        inserted,
        ToolOutcomeInsertResultV1::Inserted { .. }
    ));
    let (stored, finalizing) = inserted.into_parts();
    assert_eq!(finalizing.state(), AdmissionOperationState::Finalizing);
    assert_eq!(stored.raw_output_digest(), blob.blob_ref().digest());
    assert_eq!(fixture.authority.anchor_generation()?, anchor + 1);
    let after = observed_rows(&observer, operation.binding().operation_id().as_str())?;
    assert_eq!(after.0, before.0 + 1, "one actual Raw blob");
    assert_eq!(after.1, before.1 + 1, "one actual outcome row");
    assert_eq!(after.2, before.2 + 1, "one actual atomic claim history");
    assert_eq!(after.3, before.3 + 1, "one actual participant history");
    assert_eq!(after.4, before.4 + 2, "both actual global appends");
    let (size, retained, claimed_version): (i64, i64, i64) = observer.query_row(
        "SELECT b.blob_size_bytes,length(b.canonical_bytes),a.recovery_claimed_version
         FROM main.tool_outcome_blobs b
         JOIN main.tool_outcomes o ON o.raw_output_digest=b.digest
         JOIN main.admission_operations a ON a.operation_id=o.operation_id
         WHERE a.operation_id=?1",
        [operation.binding().operation_id().as_str()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(u64::try_from(size)?, u64::try_from(blob.bytes().len())?);
    assert_eq!(size, retained);
    assert_eq!(u64::try_from(claimed_version)?, operation.version());
    {
        let writer = fixture.outcomes.connection()?;
        assert_eq!(
            writer.query_row("PRAGMA main.cache_spill", [], |row| row.get::<_, i64>(0))?,
            writer_spill,
        );
        assert_eq!(
            writer.query_row("PRAGMA main.journal_mode", [], |row| row
                .get::<_, String>(0))?,
            writer_mode,
        );
    }
    let wal_after = main_wal_frontier(&observer)?;
    assert_eq!(wal_salts(&fixture.database)?, salts_before, "no WAL reset");
    assert_eq!(wal_after.2, wal_before.2);
    assert!(wal_after.1 >= wal_before.1);
    let written = wal_after
        .0
        .checked_sub(wal_before.0)
        .and_then(|frames| frames.checked_mul(wal_before.2))
        .ok_or("actual Raw WAL log frontier unexpectedly decreased")?;
    assert!(written > u64::try_from(blob.bytes().len())?);
    assert!(
        written > metadata,
        "Raw exceeded the seven metadata commands"
    );
    reader.execute_batch("ROLLBACK")?;
    println!(
        "Raw owning footprint: blob_bytes={}, appended_wal_bytes={written}, prewrite_wal_pressure={pressure_before}, metadata_wal_bytes={metadata}, log_before={}, log_after={}, checkpoint_before={}, checkpoint_after={}, new_blobs=1, new_outcomes=1, new_claims=1, new_participant_commits=1, new_globals=2, anchor_advance=1",
        blob.bytes().len(),
        wal_before.0,
        wal_after.0,
        wal_before.1,
        wal_after.1,
    );
    assert!(
        matches!(whole_price, Ok(price) if price >= written
            && pressure_before.checked_add(price).is_some_and(|sum| sum < 128 * 1024 * 1024)),
        "whole Raw custody transaction price omitted the actual blob, claim and participant WAL"
    );
    Ok(())
}

fn wal_salts(database: &std::path::Path) -> Result<[u8; 8], Box<dyn std::error::Error>> {
    use std::io::Read;
    let mut path = database.as_os_str().to_owned();
    path.push("-wal");
    let mut header = [0_u8; 32];
    std::fs::File::open(PathBuf::from(path))?.read_exact(&mut header)?;
    let magic = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    assert!(matches!(magic, 0x377f_0682 | 0x377f_0683));
    let mut salts = [0_u8; 8];
    salts.copy_from_slice(&header[16..24]);
    Ok(salts)
}

fn observed_rows(
    connection: &Connection,
    operation: &str,
) -> Result<(i64, i64, i64, i64, i64), rusqlite::Error> {
    connection.query_row(
        "SELECT (SELECT count(*) FROM main.tool_outcome_blobs),
                (SELECT count(*) FROM main.tool_outcomes),
                (SELECT count(*) FROM main.admission_operation_commits
                 WHERE operation_id=?1 AND mutation_kind='recovery_claim'),
                (SELECT count(*) FROM main.admission_operation_commits
                 WHERE operation_id=?1 AND mutation_kind='compare_and_swap'
                   AND participant_digest IS NOT NULL),
                (SELECT count(*) FROM main.authority_global_commits)",
        [operation],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )
}
