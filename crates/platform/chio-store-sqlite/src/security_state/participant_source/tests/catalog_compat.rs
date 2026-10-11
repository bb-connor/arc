use chio_core::{canonical_json_bytes, sha256_hex};

use super::*;

const LEGACY_CATALOG: &[u8] = include_bytes!("fixtures/security-state-critical-catalog-v0.json");
const LEGACY_CATALOG_SHA256: &str =
    "f53e9d3d441a9c639f510cf9571c9852240ca226a7adf66a13b05aeb231fe92c";
const LEGACY_SCHEMA_DIGEST: &str =
    "1db878e623b5fe5eb59fb3dc5b31d4eb8e1a7e7ffb3bddb295c7e39077b09658";

type CatalogEntry = (String, String, String, Option<String>);

fn critical_catalog(connection: &Connection) -> TestResult<Vec<CatalogEntry>> {
    let mut statement = connection.prepare(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema \
         ORDER BY type COLLATE BINARY, name COLLATE BINARY, tbl_name COLLATE BINARY",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    })?;
    let all = rows.collect::<rusqlite::Result<Vec<CatalogEntry>>>()?;
    Ok(all
        .into_iter()
        .filter(|(_, name, table, _)| {
            name.contains("security_participant_source")
                || table.contains("security_participant_source")
                || schema::TABLES.contains(&table.as_str())
                || table == "chio_store_schema_versions"
                || [
                    "security_flow_",
                    "security_declassification_",
                    "security_egress_fences",
                    "security_isolation_epochs",
                    "security_session_memberships",
                    "security_transitions",
                ]
                .iter()
                .any(|prefix| name.starts_with(prefix))
                || (name.starts_with("security_") && name.contains("flow_state"))
        })
        .collect())
}

#[test]
fn critical_catalog_keeps_the_immutable_revision0_bytes_and_seal() -> TestResult {
    assert_eq!(sha256_hex(LEGACY_CATALOG), LEGACY_CATALOG_SHA256);
    let decoded: Vec<CatalogEntry> = serde_json::from_slice(LEGACY_CATALOG)?;
    assert_eq!(canonical_json_bytes(&decoded)?, LEGACY_CATALOG);
    let mut old_preimage = b"chio.security-participant-source.catalog.v1\0".to_vec();
    old_preimage.extend_from_slice(LEGACY_CATALOG);
    assert_eq!(sha256_hex(&old_preimage), LEGACY_SCHEMA_DIGEST);

    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("security.db");
    drop(seeded_security_history(&path)?);
    let source = SqliteSecurityParticipantSource::open(&path)?;
    let expected = source.preview(&binding()?)?;
    source.seal_exact(&expected)?;
    source.verify_seal(&expected)?;
    let connection = Connection::open(&path)?;
    assert_eq!(
        canonical_json_bytes(&critical_catalog(&connection)?)?,
        LEGACY_CATALOG
    );
    let stamp: i32 = connection.query_row(
        "SELECT version FROM chio_store_schema_versions WHERE store_key = 'security_state'",
        [],
        |row| row.get(0),
    )?;
    let encoded = expected.canonical_bytes()?;
    let value: serde_json::Value = serde_json::from_slice(&encoded)?;
    if stamp == 0 {
        assert_eq!(value["catalog_digest"].as_str(), Some(LEGACY_SCHEMA_DIGEST));
    } else {
        assert_eq!(
            stamp, 1,
            "this compatibility test supports only the qualified revisions"
        );
        assert_ne!(value["catalog_digest"].as_str(), Some(LEGACY_SCHEMA_DIGEST));
    }
    let seal_before: Vec<u8> = connection.query_row(
        "SELECT canonical_bytes FROM chio_security_participant_source_seal WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    assert!(SqliteSecurityStateStore::open(&path).is_err());
    drop(source);
    let reopened = SqliteSecurityParticipantSource::open(&path)?;
    reopened.verify_seal(&expected)?;
    let retained = reopened.read_sealed_rows(&expected)?;
    assert!(retained.tables.iter().any(|(_, rows)| !rows.is_empty()));
    assert_eq!(
        connection.query_row(
            "SELECT canonical_bytes FROM chio_security_participant_source_seal WHERE singleton = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )?,
        seal_before
    );

    // The acceptance driver may additionally verify the ACTUAL prechange
    // capture after upgrade. Any configured missing/mismatched evidence fails;
    // the source is only read through its existing physical-identity API.
    if let Some(capture) = std::env::var_os("CHIO_PR1160_VERIFY_LEGACY_SOURCE_CAPTURE_DIR") {
        let capture = std::path::PathBuf::from(capture);
        let original_path =
            std::path::PathBuf::from(std::fs::read_to_string(capture.join("source-path.txt"))?);
        let expectation_bytes = std::fs::read(capture.join("source-expectation.json"))?;
        let original_seal = std::fs::read(capture.join("source-seal.json"))?;
        assert_eq!(expectation_bytes, original_seal);
        let old = SecurityParticipantSourceSnapshot::from_canonical_bytes(&expectation_bytes)?;
        let old_value: serde_json::Value = serde_json::from_slice(&expectation_bytes)?;
        assert_eq!(
            old_value["catalog_digest"].as_str(),
            Some(LEGACY_SCHEMA_DIGEST)
        );
        let file_before = sha256_hex(&std::fs::read(&original_path)?);
        let original = SqliteSecurityParticipantSource::open(&original_path)?;
        original.verify_seal(&old)?;
        let actual_seal = original.load_seal()?.ok_or("retained old seal is absent")?;
        assert_eq!(actual_seal.snapshot().canonical_bytes()?, original_seal);
        let retained = original.read_sealed_rows(&old)?;
        assert!(retained.tables.iter().any(|(_, rows)| !rows.is_empty()));
        drop(original);
        assert_eq!(sha256_hex(&std::fs::read(&original_path)?), file_before);
        assert_eq!(
            std::fs::read(capture.join("source-expectation.json"))?,
            expectation_bytes
        );
        assert_eq!(
            std::fs::read(capture.join("source-seal.json"))?,
            original_seal
        );
    }

    // Root may explicitly retain the genuine prechange inode and expectation
    // for an old-seal read/import capture after the producer changes. This does
    // not synthesize or copy a seal, and never overwrites an earlier capture.
    if let Some(output) = std::env::var_os("CHIO_PR1160_LEGACY_SOURCE_CAPTURE_DIR") {
        assert_eq!(
            stamp, 0,
            "legacy capture must run before the producer revision bump"
        );
        let output = std::path::PathBuf::from(output);
        std::fs::create_dir_all(&output)?;
        for name in [
            "source-path.txt",
            "source-expectation.json",
            "source-seal.json",
        ] {
            assert!(!output.join(name).exists(), "legacy capture already exists");
        }
        drop(reopened);
        drop(connection);
        let retained_directory = directory.keep();
        let retained_path = retained_directory.join("security.db");
        std::fs::write(
            output.join("source-path.txt"),
            retained_path.as_os_str().as_encoded_bytes(),
        )?;
        std::fs::write(output.join("source-expectation.json"), encoded)?;
        std::fs::write(output.join("source-seal.json"), seal_before)?;
    }
    Ok(())
}

#[test]
fn source_refuses_revision_and_finality_schema_combinations_without_repair() -> TestResult {
    for damage in ["zero-with-marker", "one-without-marker", "future-version"] {
        let directory = chio_test_support::private_tempdir()?;
        let path = directory.path().join("security.db");
        drop(seeded_security_history(&path)?);
        let connection = Connection::open(&path)?;
        let stamp: i32 = connection.query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key = 'security_state'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(
            stamp, 1,
            "this is a forward revision1 compatibility control"
        );
        match damage {
            "zero-with-marker" => {
                connection.execute(
                "UPDATE chio_store_schema_versions SET version = 0 WHERE store_key = 'security_state'", [],
            )?;
            }
            "one-without-marker" => connection.execute_batch(
                "DROP TRIGGER security_response_effect_finality_immutable; \
                 DROP TRIGGER security_response_effect_finality_delete_rejected; \
                 DROP TABLE security_response_effect_finality;",
            )?,
            "future-version" => {
                connection.execute(
                "UPDATE chio_store_schema_versions SET version = 2 WHERE store_key = 'security_state'", [],
            )?;
            }
            _ => return Err("unknown compatibility damage".into()),
        }
        let schema_before: i64 =
            connection.query_row("PRAGMA schema_version", [], |row| row.get(0))?;
        let data_before: i64 = connection.query_row("PRAGMA data_version", [], |row| row.get(0))?;
        let version_before: i32 = connection.query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key = 'security_state'",
            [],
            |row| row.get(0),
        )?;
        let reason = match damage {
            "zero-with-marker" => "source version and finality schema disagree",
            "one-without-marker" => "source finality schema is not qualified",
            "future-version" => "source security schema version is not canonical",
            _ => return Err("unknown compatibility damage".into()),
        };
        let error = SqliteSecurityParticipantSource::open(&path)
            .err()
            .ok_or("invalid source revision/schema combination was accepted")?;
        assert!(
            matches!(error, Error::Invalid(actual) if actual == reason),
            "{damage}: {error}"
        );
        assert_eq!(
            connection.query_row("PRAGMA schema_version", [], |row| row.get::<_, i64>(0))?,
            schema_before
        );
        assert_eq!(
            connection.query_row("PRAGMA data_version", [], |row| row.get::<_, i64>(0))?,
            data_before
        );
        assert_eq!(
            connection.query_row(
                "SELECT version FROM chio_store_schema_versions WHERE store_key = 'security_state'",
                [],
                |row| row.get::<_, i32>(0),
            )?,
            version_before
        );
        assert!(!schema::has_evidence(&connection)?);
    }
    Ok(())
}

#[test]
fn revision1_seal_cannot_be_laundered_into_legacy0_by_removing_marker_schema() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("security.db");
    drop(seeded_security_history(&path)?);
    let source = SqliteSecurityParticipantSource::open(&path)?;
    let expected = source.preview(&binding()?)?;
    source.seal_exact(&expected)?;
    let connection = Connection::open(&path)?;
    let version: i32 = connection.query_row(
        "SELECT version FROM chio_store_schema_versions WHERE store_key = 'security_state'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(version, 1, "this is a forward revision1 seal control");
    let original_seal: Vec<u8> = connection.query_row(
        "SELECT canonical_bytes FROM chio_security_participant_source_seal WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let version_trigger: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = 'chio_security_participant_source_version_no_update'",
        [], |row| row.get(0),
    )?;
    connection.execute_batch(
        "DROP TRIGGER chio_security_participant_source_version_no_update; \
         DROP TRIGGER security_response_effect_finality_immutable; \
         DROP TRIGGER security_response_effect_finality_delete_rejected; \
         DROP TABLE security_response_effect_finality; \
         UPDATE chio_store_schema_versions SET version = 0 WHERE store_key = 'security_state';",
    )?;
    connection.execute_batch(&version_trigger)?;
    assert_eq!(
        canonical_json_bytes(&critical_catalog(&connection)?)?,
        LEGACY_CATALOG,
        "the attack restored the complete genuine old critical catalog"
    );
    let before_schema: i64 = connection.query_row("PRAGMA schema_version", [], |row| row.get(0))?;
    let before_data: i64 = connection.query_row("PRAGMA data_version", [], |row| row.get(0))?;
    let error = source
        .verify_seal(&expected)
        .err()
        .ok_or("downgraded source authenticated the current seal")?;
    assert!(
        matches!(
            error,
            Error::Invalid("source differs from pinned expectation")
        ),
        "{error}"
    );
    drop(source);
    let error = SqliteSecurityParticipantSource::open(&path)
        .err()
        .ok_or("a revision1 seal authenticated under the restored old schema/version")?;
    assert!(
        matches!(
            error,
            Error::Invalid("source differs from pinned expectation")
        ),
        "{error}"
    );
    assert_eq!(
        connection.query_row(
            "SELECT canonical_bytes FROM chio_security_participant_source_seal WHERE singleton = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )?,
        original_seal
    );
    assert_eq!(
        connection.query_row("PRAGMA schema_version", [], |row| row.get::<_, i64>(0))?,
        before_schema
    );
    assert_eq!(
        connection.query_row("PRAGMA data_version", [], |row| row.get::<_, i64>(0))?,
        before_data
    );
    Ok(())
}
