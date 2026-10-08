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
