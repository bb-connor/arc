//! Same-format codec catalog transition through the real authority open path.
use super::*;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, PartialEq)]
struct History {
    records: Vec<(String, i64, Vec<u8>)>,
    events: Vec<(i64, String)>,
    commits: Vec<(i64, String)>,
}

struct Authority {
    _directory: tempfile::TempDir,
    database: std::path::PathBuf,
    locks: std::path::PathBuf,
}

impl Authority {
    fn provisioned() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let database = directory.path().join("authority.db");
        let locks = directory.path().join("locks");
        std::fs::DirBuilder::new().mode(0o700).create(&locks)?;
        crate::SqliteAuthorityStore::provision(&database, &locks)?;
        drop(crate::SqliteAuthorityStore::open_serving(
            &database, &locks,
        )?);
        Ok(Self {
            _directory: directory,
            database,
            locks,
        })
    }

    fn open(&self) -> Result<crate::SqliteAuthorityStore, Box<dyn std::error::Error>> {
        Ok(crate::SqliteAuthorityStore::open_serving(
            &self.database,
            &self.locks,
        )?)
    }

    fn connection(&self) -> TestResult<Connection> {
        Ok(Connection::open(&self.database)?)
    }

    /// Retain real protected history through the serving writer: each record
    /// has its event and its global commit before the catalog changes.
    fn populate(&self, count: usize) -> TestResult {
        let authority = self.open()?;
        let store = authority.admission_operation_store();
        let scope = "0".repeat(64);
        for ordinal in 0..count {
            let mut connection = store.connection()?;
            let tx = store.begin_write(&mut connection, None)?;
            super::super::super::recovery::storage::save(
                &tx,
                &store.serving_owner,
                &format!("knowledge-pin:{scope}:catalog-history-{ordinal}"),
                &scope,
                "command",
                &super::super::super::recovery::storage::encode(&format!(
                    "retained-history-{ordinal}"
                ))?,
                None,
            )?;
            store.commit_write(tx)?;
            store.sync_after_write(&connection)?;
        }
        Ok(())
    }

    /// Install the exact prior supported catalog (A): the prior guard pair
    /// and no release lookup index, as a store created before release roots
    /// and chunks were admitted carries it.
    fn with_prior_guards(&self) -> TestResult {
        self.connection()?
            .execute_batch("DROP INDEX idx_recovery_knowledge_join_release;")?;
        let connection = self.connection()?;
        for guard in CODEC_GUARDS {
            connection.execute_batch(&format!("DROP TRIGGER {guard};"))?;
        }
        connection.execute_batch(PRIOR_CODEC_GUARDS)?;
        Ok(())
    }

    /// The exact current codec guards without only the release lookup index
    /// (B): the supported predecessor this repair itself upgrades.
    fn without_release_index(&self) -> TestResult {
        self.connection()?
            .execute_batch("DROP INDEX idx_recovery_knowledge_join_release;")?;
        Ok(())
    }

    fn catalog(&self) -> TestResult<Vec<(String, Option<String>)>> {
        let connection = self.connection()?;
        let mut statement =
            connection.prepare("SELECT name,sql FROM sqlite_schema ORDER BY type,name")?;
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<_, _>>()?;
        Ok(rows)
    }

    /// Retained protected records, their exact event history and the global
    /// commit chain.
    fn history(&self) -> TestResult<History> {
        let connection = self.connection()?;
        let mut records = connection.prepare(
            "SELECT record_key,version,payload FROM admission_operation_recovery_records ORDER BY record_key",
        )?;
        let records = records
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<Result<_, _>>()?;
        let mut events = connection.prepare(
            "SELECT sequence,event_digest FROM admission_operation_recovery_events ORDER BY sequence",
        )?;
        let events = events
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<_, _>>()?;
        let mut commits = connection.prepare(
            "SELECT commit_sequence,chain_digest FROM authority_global_commits ORDER BY commit_sequence",
        )?;
        let commits = commits
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<_, _>>()?;
        Ok(History {
            records,
            events,
            commits,
        })
    }

    fn current_catalog(&self) -> TestResult<bool> {
        let connection = self.connection()?;
        Ok(verify_admission_operation_schema(
            &connection,
            ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION,
        )
        .is_ok())
    }
}

#[test]
fn release_codec_catalog_fresh_store_installs_the_current_guards_and_release_index() -> TestResult {
    let authority = Authority::provisioned()?;
    assert!(authority.current_catalog()?);
    let (kind, table): (String, String) = authority.connection()?.query_row(
        "SELECT type,tbl_name FROM sqlite_schema WHERE name='idx_recovery_knowledge_join_release'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(kind, "index");
    assert_eq!(table, "admission_operation_recovery_records");
    Ok(())
}

#[test]
fn release_codec_catalog_transitions_the_exact_prior_supported_catalog_once() -> TestResult {
    let authority = Authority::provisioned()?;
    let empty = authority.history()?;
    authority.populate(3)?;
    authority.with_prior_guards()?;
    assert!(!authority.current_catalog()?);
    let history = authority.history()?;
    assert_eq!(history.records.len(), empty.records.len() + 3);
    assert!(history.events.len() >= empty.events.len() + 3);
    assert!(history.commits.len() >= empty.commits.len() + 3);
    drop(authority.open()?);
    assert!(authority.current_catalog()?);
    assert_eq!(
        authority.history()?,
        history,
        "the transition rewrites no row"
    );
    // The current catalog opens with no further transition.
    let catalog = authority.catalog()?;
    drop(authority.open()?);
    assert_eq!(authority.catalog()?, catalog);
    assert_eq!(authority.history()?, history);
    Ok(())
}

#[test]
fn release_codec_catalog_transitions_the_current_guards_without_the_release_index() -> TestResult {
    let authority = Authority::provisioned()?;
    let empty = authority.history()?;
    authority.populate(3)?;
    authority.without_release_index()?;
    assert!(!authority.current_catalog()?);
    let history = authority.history()?;
    assert_eq!(history.records.len(), empty.records.len() + 3);
    drop(authority.open()?);
    assert!(authority.current_catalog()?);
    assert_eq!(
        authority.history()?,
        history,
        "the index-only transition rewrites no row"
    );
    // The current catalog opens with no further transition.
    let catalog = authority.catalog()?;
    drop(authority.open()?);
    assert_eq!(authority.catalog()?, catalog);
    assert_eq!(authority.history()?, history);
    Ok(())
}

#[test]
fn release_codec_catalog_refuses_a_prior_catalog_with_the_release_index() -> TestResult {
    let authority = Authority::provisioned()?;
    // Prior guards while the release index remains: not an admitted catalog.
    let connection = authority.connection()?;
    for guard in CODEC_GUARDS {
        connection.execute_batch(&format!("DROP TRIGGER {guard};"))?;
    }
    connection.execute_batch(PRIOR_CODEC_GUARDS)?;
    let (catalog, history) = (authority.catalog()?, authority.history()?);
    assert!(authority.open().is_err());
    assert_eq!(authority.catalog()?, catalog);
    assert_eq!(authority.history()?, history);
    Ok(())
}

#[test]
fn release_codec_catalog_refuses_a_forged_release_index_without_mutation() -> TestResult {
    let authority = Authority::provisioned()?;
    authority.connection()?.execute_batch(
        "DROP INDEX idx_recovery_knowledge_join_release;
         CREATE INDEX idx_recovery_knowledge_join_release
         ON admission_operation_recovery_records(record_key)
         WHERE record_key GLOB 'knowledge-join:*';",
    )?;
    let (catalog, history) = (authority.catalog()?, authority.history()?);
    assert!(authority.open().is_err());
    assert_eq!(
        authority.catalog()?,
        catalog,
        "a forged same-name index is refused without repair or removal"
    );
    assert_eq!(authority.history()?, history);
    Ok(())
}

#[test]
fn release_codec_catalog_refuses_an_extra_catalog_object_without_mutation() -> TestResult {
    let authority = Authority::provisioned()?;
    authority.without_release_index()?;
    authority.connection()?.execute_batch(
        "CREATE INDEX admission_operation_release_index_probe
         ON admission_operation_recovery_records(kind);",
    )?;
    let (catalog, history) = (authority.catalog()?, authority.history()?);
    assert!(authority.open().is_err());
    assert_eq!(authority.catalog()?, catalog);
    assert_eq!(authority.history()?, history);
    Ok(())
}

#[test]
fn release_codec_catalog_refuses_a_partial_prior_catalog_without_mutation() -> TestResult {
    let authority = Authority::provisioned()?;
    authority.with_prior_guards()?;
    authority
        .connection()?
        .execute_batch("DROP TRIGGER admission_operation_recovery_codec_guard_update;")?;
    let (catalog, history) = (authority.catalog()?, authority.history()?);
    assert!(authority.open().is_err());
    assert_eq!(authority.catalog()?, catalog);
    assert_eq!(authority.history()?, history);
    Ok(())
}

#[test]
fn release_codec_catalog_refuses_a_prior_catalog_whose_inventory_fails() -> TestResult {
    let authority = Authority::provisioned()?;
    authority.with_prior_guards()?;
    // A protected record without its event history fails the full inventory.
    authority.connection()?.execute(
        "INSERT INTO admission_operation_recovery_records(record_key,scope_key,kind,version,payload)
         VALUES ('knowledge-orphan',?1,'command',1,X'7B7D')",
        params!["0".repeat(64)],
    )?;
    let (catalog, history) = (authority.catalog()?, authority.history()?);
    assert!(authority.open().is_err());
    assert_eq!(
        authority.catalog()?,
        catalog,
        "a rejected inventory keeps the exact prior catalog"
    );
    assert_eq!(authority.history()?, history);
    Ok(())
}
