//! Paired old-producer capture and current-producer import through the SAME
//! physical source and independently provisioned destination. Artifact data is
//! comparison evidence; the live owner and Source APIs establish authority.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use chio_core::canonical_json_bytes;
use serde::{Deserialize, Serialize};

use super::*;

const MODE_ENV: &str = "CHIO_PR1160_LEGACY_OWNER_PAIR_MODE";
const DIRECTORY_ENV: &str = "CHIO_PR1160_LEGACY_OWNER_PAIR_CAPTURE_DIR";
const LEGACY_DIGEST: &str = "1db878e623b5fe5eb59fb3dc5b31d4eb8e1a7e7ffb3bddb295c7e39077b09658";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Capture {
    fixture_root: PathBuf,
    old_fence: StoreMutationFence,
    expectation_id: String,
    schema_revision: i32,
    source_sha256: String,
    source_identity: (u64, u64, u64),
    destination_identity: (u64, u64, u64),
    lock_identity: (u64, u64, u64),
    lock_root_identity: (u64, u64),
    global_commits: i64,
    anchor_generation: u64,
}

#[test]
fn paired_source_import_preserves_the_real_owner_and_exact_retained_rows() -> AnchoredTestResult {
    match (std::env::var_os(MODE_ENV), std::env::var_os(DIRECTORY_ENV)) {
        (Some(mode), Some(directory)) => {
            let directory = PathBuf::from(directory);
            match mode.to_str() {
                Some("capture") => {
                    capture_pair(&directory, true, true)?;
                    eprintln!("ACTUAL_LEGACY0_OWNER_PAIR_CAPTURE {}", directory.display());
                    Ok(())
                }
                Some("verify") => {
                    require_current_writer()?;
                    verify_pair(&directory, true)?;
                    eprintln!("ACTUAL_LEGACY0_OWNER_PAIR_IMPORTED {}", directory.display());
                    Ok(())
                }
                _ => Err("legacy owner pair mode must be capture or verify".into()),
            }
        }
        (None, None) => {
            // Ordinary suites run a real self-contained owner-restart/import
            // control. Only explicitly configured runs qualify an OLD capture.
            let artifacts = tempfile::tempdir()?;
            let directory = artifacts.path().join("capture");
            let _fixture_guard = capture_pair(&directory, false, false)?;
            verify_pair(&directory, false)
        }
        _ => Err("requested legacy owner pair mode and capture directory are both required".into()),
    }
}

fn file_identity(path: &Path) -> AnchoredTestResult<(u64, u64, u64)> {
    let metadata = fs::metadata(path)?;
    Ok((metadata.dev(), metadata.ino(), metadata.nlink()))
}

fn source_revision(path: &Path) -> AnchoredTestResult<i32> {
    let connection = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    Ok(connection.query_row(
        "SELECT version FROM chio_store_schema_versions WHERE store_key = 'security_state'",
        [],
        |row| row.get(0),
    )?)
}

fn require_current_writer() -> AnchoredTestResult {
    let probe = tempfile::tempdir()?;
    secure_directory(probe.path());
    let path = probe.path().join("current-writer.db");
    drop(crate::SqliteSecurityStateStore::open(&path)?);
    assert_eq!(
        source_revision(&path)?,
        1,
        "verify requires the current producer"
    );
    Ok(())
}

fn capture_pair(
    output: &Path,
    keep_fixture: bool,
    require_legacy: bool,
) -> AnchoredTestResult<Option<TempDir>> {
    // create_dir refuses ANY prior output, including a partial failed capture.
    fs::create_dir(output)?;
    secure_directory(output);
    let fixture = fixture();
    let source_path = fixture._temp.path().join("security-source.db");
    let source = source(&fixture)?;
    let schema_revision = source_revision(&source_path)?;
    if require_legacy {
        assert_eq!(schema_revision, 0, "capture requires the old producer");
        let connection =
            Connection::open_with_flags(&source_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let markers: i64 = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name LIKE 'security_response_effect_finality%'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(markers, 0);
    }
    let before = global_count(&fixture)?;
    let expected = pin(&fixture, &source)?;
    assert_eq!(
        expected.phase(),
        SecurityParticipantMigrationPhase::Expected
    );
    assert_eq!(global_count(&fixture)?, before + 1);
    let binding = expected.snapshot().binding();
    assert_eq!(binding.source_id().as_str(), "private-source");
    assert_eq!(
        binding.security_authority_id().as_str(),
        authority_id().as_str()
    );
    assert_eq!(
        binding.destination_store_uuid().as_str(),
        fixture.fence.store_uuid
    );
    let uuid = uuid::Uuid::parse_str(&fixture.fence.store_uuid)?;
    assert_eq!(uuid.get_version_num(), 7);
    assert_eq!(uuid.to_string(), fixture.fence.store_uuid);
    let snapshot = expected.snapshot().canonical_bytes()?;
    if require_legacy {
        let value: serde_json::Value = serde_json::from_slice(&snapshot)?;
        assert_eq!(value["catalog_digest"].as_str(), Some(LEGACY_DIGEST));
    }
    let seal = source.seal_exact(expected.snapshot())?;
    source.verify_seal(expected.snapshot())?;
    assert_eq!(seal.snapshot().canonical_bytes()?, snapshot);
    assert_eq!(load(&fixture)?, Some(expected.clone()));
    let rows = source.read_sealed_rows(expected.snapshot())?;
    assert!(rows.tables.iter().any(|(_, rows)| !rows.is_empty()));
    let source_rows = canonical_json_bytes(&rows.tables)?;
    let lock_path = fixture
        .lock_root
        .join(format!("{}.lock", fixture.fence.store_uuid));
    let mut capture = Capture {
        fixture_root: fixture._temp.path().to_path_buf(),
        old_fence: fixture.fence.clone(),
        expectation_id: expected.expectation_id().as_str().to_owned(),
        schema_revision,
        source_sha256: String::new(),
        source_identity: file_identity(&source_path)?,
        destination_identity: file_identity(&fixture.database)?,
        lock_identity: file_identity(&lock_path)?,
        lock_root_identity: {
            let metadata = fs::metadata(&fixture.lock_root)?;
            (metadata.dev(), metadata.ino())
        },
        global_commits: global_count(&fixture)?,
        anchor_generation: fixture.authority.anchor_generation()?,
    };
    drop(source);
    let Fixture {
        _temp,
        store,
        authority,
        ..
    } = fixture;
    drop(store);
    drop(authority);
    // Retain the complete original private directory only after every writer
    // and owner handle is closed. No file is relocated or copied as authority.
    let guard = if keep_fixture {
        assert_eq!(_temp.keep(), capture.fixture_root);
        None
    } else {
        Some(_temp)
    };
    capture.source_sha256 = sha256_hex(&fs::read(&source_path)?);
    fs::write(output.join("source-expectation.json"), &snapshot)?;
    fs::write(
        output.join("source-seal.json"),
        seal.snapshot().canonical_bytes()?,
    )?;
    fs::write(output.join("source-rows.json"), source_rows)?;
    fs::write(output.join("capture.json"), canonical_json_bytes(&capture)?)?;
    Ok(guard)
}

fn verify_pair(directory: &Path, require_legacy: bool) -> AnchoredTestResult {
    let capture_bytes = fs::read(directory.join("capture.json"))?;
    let capture: Capture = serde_json::from_slice(&capture_bytes)?;
    assert_eq!(canonical_json_bytes(&capture)?, capture_bytes);
    if require_legacy {
        assert_eq!(capture.schema_revision, 0);
    }
    let source_path = capture.fixture_root.join("security-source.db");
    let database = capture.fixture_root.join("authority.db");
    let lock_root = capture.fixture_root.join("locks");
    let lock_path = lock_root.join(format!("{}.lock", capture.old_fence.store_uuid));
    let snapshot_bytes = fs::read(directory.join("source-expectation.json"))?;
    let seal_bytes = fs::read(directory.join("source-seal.json"))?;
    let row_bytes = fs::read(directory.join("source-rows.json"))?;
    assert_eq!(snapshot_bytes, seal_bytes);
    let snapshot = crate::security_state::SecurityParticipantSourceSnapshot::from_canonical_bytes(
        &snapshot_bytes,
    )?;
    assert_eq!(source_revision(&source_path)?, capture.schema_revision);
    assert_eq!(file_identity(&source_path)?, capture.source_identity);
    assert_eq!(file_identity(&database)?, capture.destination_identity);
    assert_eq!(file_identity(&lock_path)?, capture.lock_identity);
    let metadata = fs::metadata(&lock_root)?;
    assert_eq!((metadata.dev(), metadata.ino()), capture.lock_root_identity);
    assert_eq!(sha256_hex(&fs::read(&source_path)?), capture.source_sha256);
    // This constructor verifies the actual provisioned path/lock/anchor and
    // opens a fresh lease. The captured old fence is NEVER passed as authority.
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    authority.verify_database_path(&database)?;
    let fence = authority.mutation_fence();
    assert_eq!(fence.store_uuid, capture.old_fence.store_uuid);
    assert!(fence.owner_epoch > capture.old_fence.owner_epoch);
    assert_ne!(fence.lease_id, capture.old_fence.lease_id);
    assert!(authority.anchor_generation()? > capture.anchor_generation);
    let store = authority.admission_operation_store();
    // Load independent custody BEFORE import. Never create a new expectation
    // from the artifact snapshot or repin this already retired source.
    let expected = store
        .load_security_participant_migration(&authority_id(), &fence, now_ms())?
        .ok_or("retained destination expectation is absent")?;
    assert_eq!(
        expected.phase(),
        SecurityParticipantMigrationPhase::Expected
    );
    assert_eq!(expected.expectation_id().as_str(), capture.expectation_id);
    assert_eq!(expected.snapshot().canonical_bytes()?, snapshot_bytes);
    assert_eq!(expected.snapshot(), &snapshot);
    let source = SqliteSecurityParticipantSource::open(&source_path)?;
    source.verify_seal(&snapshot)?;
    assert_eq!(
        source
            .load_seal()?
            .ok_or("retained source seal is absent")?
            .snapshot()
            .canonical_bytes()?,
        seal_bytes
    );
    let retained = source.read_sealed_rows(&snapshot)?;
    assert_eq!(canonical_json_bytes(&retained.tables)?, row_bytes);
    let global_count = || -> AnchoredTestResult<i64> {
        Ok(store.connection()?.query_row(
            "SELECT COUNT(*) FROM authority_global_commits",
            [],
            |row| row.get(0),
        )?)
    };
    assert_eq!(global_count()?, capture.global_commits);
    let anchored_before = authority.anchor_generation()?;
    let imported = store.import_security_participant_source(
        &authority_id(),
        expected.expectation_id(),
        &source,
        &fence,
        now_ms(),
    )?;
    assert_eq!(
        imported.phase(),
        SecurityParticipantMigrationPhase::ImportedInactive
    );
    assert_eq!(imported.snapshot(), expected.snapshot());
    assert_eq!(global_count()?, capture.global_commits + 1);
    let anchored_after = authority.anchor_generation()?;
    assert!(anchored_after > anchored_before);
    {
        let connection = store.connection()?;
        let mut total = 0_i64;
        for (table, rows) in retained.tables {
            let mut statement = connection.prepare(
                "SELECT canonical_row FROM security_participant_migration_rows \
                 WHERE security_authority_id = ?1 AND table_name = ?2 ORDER BY row_index",
            )?;
            let actual = statement
                .query_map(params![authority_id().as_str(), table], |row| {
                    row.get::<_, Vec<u8>>(0)
                })?
                .collect::<Result<Vec<_>, _>>()?;
            assert_eq!(actual, rows, "actual original row bytes: {table}");
            total += i64::try_from(rows.len())?;
        }
        assert_eq!(
            connection.query_row(
                "SELECT COUNT(*) FROM security_participant_migration_rows",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            total
        );
        assert_eq!(
            connection.query_row("SELECT COUNT(*) FROM admission_operations", [], |row| row
                .get::<_, i64>(
                0
            ))?,
            0
        );
        assert_eq!(
            connection.query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name = 'security_flow_contexts'",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            0
        );
    }
    assert_eq!(
        store.import_security_participant_source(
            &authority_id(),
            expected.expectation_id(),
            &source,
            &fence,
            now_ms()
        )?,
        imported
    );
    assert_eq!(global_count()?, capture.global_commits + 1);
    assert_eq!(authority.anchor_generation()?, anchored_after);
    source.verify_seal(&snapshot)?;
    assert_eq!(
        canonical_json_bytes(&source.read_sealed_rows(&snapshot)?.tables)?,
        row_bytes
    );
    drop(source);
    drop(store);
    drop(authority);
    assert_eq!(file_identity(&source_path)?, capture.source_identity);
    assert_eq!(sha256_hex(&fs::read(&source_path)?), capture.source_sha256);
    for (name, bytes) in [
        ("capture.json", capture_bytes),
        ("source-expectation.json", snapshot_bytes),
        ("source-seal.json", seal_bytes),
        ("source-rows.json", row_bytes),
    ] {
        assert_eq!(fs::read(directory.join(name))?, bytes);
    }
    Ok(())
}
