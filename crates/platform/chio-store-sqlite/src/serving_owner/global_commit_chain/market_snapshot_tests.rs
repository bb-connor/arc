use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Fixture {
    connection: Connection,
    authority: crate::SqliteAuthorityStore,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        crate::test_authority::secure_directory(directory.path());
        let database = directory.path().join("authority.db");
        let locks = directory.path().join("locks");
        std::fs::create_dir(&locks)?;
        crate::test_authority::secure_directory(&locks);
        crate::SqliteAuthorityStore::provision(&database, &locks)?;
        let authority = crate::test_authority::open_serving(&database, &locks)?;
        let connection = Connection::open(database)?;
        Ok(Self {
            connection,
            authority,
            _directory: directory,
        })
    }

    fn install_projection(&mut self, snapshot: &str) -> TestResult {
        let transaction = self.connection.transaction()?;
        let mutation_kind = "finding_challenge_write";
        let commit_digest = digest(&FindingChallengeProjectionEntry {
            format: "chio.sqlite-finding-challenge-projection.v1",
            previous_commit_digest: GLOBAL_GENESIS_DIGEST,
            projection_sequence: 1,
            mutation_kind,
            snapshot_digest: snapshot,
        })?;
        transaction.execute(
            "INSERT INTO finding_challenge_projection_commits (
                projection_sequence, mutation_kind, snapshot_digest,
                previous_commit_digest, commit_digest
            ) VALUES (1, ?1, ?2, ?3, ?4)",
            params![
                mutation_kind,
                snapshot,
                GLOBAL_GENESIS_DIGEST,
                commit_digest
            ],
        )?;
        append_global_commit(
            &transaction,
            mutation_kind,
            "finding_challenge",
            "market",
            1,
            &self.authority.mutation_fence(),
        )?;
        transaction.commit()?;
        Ok(())
    }
}

const EXPECTED_MARKET_TABLES: &[&str] = &[
    "challenges",
    "dispute_lock_reservations",
    "dispute_locks",
    "liability_heads",
    "governance_case_index",
    "claim_snapshots",
    "effect_intents",
    "listing_sales_blocks",
    "effect_root_bindings",
    "effect_root_bindings_refreshes",
    "finding_challenge_outcomes",
    "finding_finalizing_authorizations",
    "finding_finalizing_authorization_refreshes",
    "finding_seller_impairment_reconciliations",
    "finding_challenge_submissions",
    "purchase_records",
    "purchase_capture_intents",
    "failed_delivery_records",
    "purchase_reservations",
    "public_purchase_requests",
    "purchase_payout_bindings",
    "seller_exposure_encumbrances",
    "pending_purchase_slots",
    "payout_destinations",
];

fn snapshot_fixture(
    connection: &Connection,
    format: &str,
    omitted_table: Option<&str>,
) -> Result<String, SqliteServingOwnerError> {
    let tables = EXPECTED_MARKET_TABLES
        .iter()
        .copied()
        .filter(|table| Some(*table) != omitted_table)
        .map(|table| table_snapshot(connection, table, None))
        .collect::<Result<Vec<_>, _>>()?;
    digest(&serde_json::json!({ "format": format, "tables": tables }))
}

fn assert_projection_refused(format: &str, omitted_table: Option<&str>) -> TestResult {
    let mut fixture = Fixture::new()?;
    let snapshot = snapshot_fixture(&fixture.connection, format, omitted_table)?;
    fixture.install_projection(&snapshot)?;
    match verify_finding_challenge_projection_coverage(&fixture.connection) {
        Err(SqliteServingOwnerError::Invalid(detail)) => assert_eq!(
            detail,
            "finding challenge projection does not cover current state"
        ),
        other => panic!("expected exact snapshot coverage refusal, got {other:?}"),
    }
    let retained: String = fixture.connection.query_row(
        "SELECT snapshot_digest FROM finding_challenge_projection_commits WHERE projection_sequence = 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(retained, snapshot);
    Ok(())
}

#[test]
fn market_snapshot_producer_uses_the_complete_v1_domain() -> TestResult {
    let fixture = Fixture::new()?;
    assert_eq!(
        finding_market_snapshot_digest(&fixture.connection)?,
        snapshot_fixture(
            &fixture.connection,
            "chio.sqlite-finding-market-snapshot.v1",
            None,
        )?
    );
    Ok(())
}

#[test]
fn complete_v1_market_projection_is_accepted() -> TestResult {
    let mut fixture = Fixture::new()?;
    let snapshot = snapshot_fixture(
        &fixture.connection,
        "chio.sqlite-finding-market-snapshot.v1",
        None,
    )?;
    fixture.install_projection(&snapshot)?;
    verify_finding_challenge_projection_coverage(&fixture.connection)?;
    Ok(())
}

#[test]
fn non_v1_market_domain_is_refused() -> TestResult {
    assert_projection_refused(
        &["chio.sqlite-finding-market-snapshot.v1", "2"].concat(),
        None,
    )
}

#[test]
fn historical_projection_omitting_challenge_submissions_is_refused() -> TestResult {
    assert_projection_refused(
        &["chio.sqlite-finding-market-snapshot.v1", "2"].concat(),
        Some("finding_challenge_submissions"),
    )
}

#[test]
fn v1_projection_omitting_challenge_submissions_is_refused() -> TestResult {
    assert_projection_refused(
        "chio.sqlite-finding-market-snapshot.v1",
        Some("finding_challenge_submissions"),
    )
}

#[test]
fn v1_projection_omitting_root_binding_refreshes_is_refused() -> TestResult {
    assert_projection_refused(
        "chio.sqlite-finding-market-snapshot.v1",
        Some("effect_root_bindings_refreshes"),
    )
}

#[test]
fn v1_projection_omitting_public_purchase_requests_is_refused() -> TestResult {
    assert_projection_refused(
        "chio.sqlite-finding-market-snapshot.v1",
        Some("public_purchase_requests"),
    )
}

fn table_coverage_fixture() -> Result<Connection, Box<dyn std::error::Error>> {
    let connection = Connection::open_in_memory()?;
    for table in EXPECTED_MARKET_TABLES {
        connection.execute_batch(&format!("CREATE TABLE {table} (value TEXT NOT NULL);"))?;
    }
    connection.execute_batch(
        "CREATE TABLE finding_challenge_projection_commits (
            projection_sequence INTEGER, mutation_kind TEXT, snapshot_digest TEXT,
            previous_commit_digest TEXT, commit_digest TEXT
        );
        CREATE TABLE authority_global_commits (
            projection_kind TEXT, projection_key TEXT, projection_sequence INTEGER
        );",
    )?;
    Ok(connection)
}

#[test]
fn every_market_table_requires_an_authenticated_projection_when_populated() -> TestResult {
    let connection = table_coverage_fixture()?;
    verify_finding_challenge_projection_coverage(&connection)?;
    for table in EXPECTED_MARKET_TABLES {
        connection.execute(&format!("INSERT INTO {table} VALUES ('state')"), [])?;
        match verify_finding_challenge_projection_coverage(&connection) {
            Err(SqliteServingOwnerError::Invalid(detail)) => assert_eq!(
                detail, "finding challenge state has no authenticated projection",
                "{table}",
            ),
            other => panic!("expected missing projection refusal for {table}, got {other:?}"),
        }
        connection.execute(&format!("DELETE FROM {table}"), [])?;
    }
    Ok(())
}

#[test]
fn every_market_table_binds_its_populated_rows_into_the_snapshot() -> TestResult {
    for table in EXPECTED_MARKET_TABLES {
        let connection = table_coverage_fixture()?;
        connection.execute(&format!("INSERT INTO {table} VALUES ('committed')"), [])?;
        let snapshot =
            snapshot_fixture(&connection, "chio.sqlite-finding-market-snapshot.v1", None)?;
        let commit = digest(&FindingChallengeProjectionEntry {
            format: "chio.sqlite-finding-challenge-projection.v1",
            previous_commit_digest: GLOBAL_GENESIS_DIGEST,
            projection_sequence: 1,
            mutation_kind: "finding_challenge_write",
            snapshot_digest: &snapshot,
        })?;
        connection.execute(
            "INSERT INTO finding_challenge_projection_commits VALUES (1, 'finding_challenge_write', ?1, ?2, ?3)",
            params![snapshot, GLOBAL_GENESIS_DIGEST, commit],
        )?;
        connection.execute(
            "INSERT INTO authority_global_commits VALUES ('finding_challenge', 'market', 1)",
            [],
        )?;
        verify_finding_challenge_projection_coverage(&connection)?;
        connection.execute(&format!("DELETE FROM {table}"), [])?;
        match verify_finding_challenge_projection_coverage(&connection) {
            Err(SqliteServingOwnerError::Invalid(detail)) => assert_eq!(
                detail, "finding challenge projection does not cover current state",
                "{table}",
            ),
            other => panic!("expected row coverage refusal for {table}, got {other:?}"),
        }
    }
    Ok(())
}
