//! Exact immutable native observation backing an original private release.
use super::*;

/// One constant indexed candidate routing query over the knowledge-join
/// retained history. The index routes candidates only; it grants no authority.
/// A missing or unusable index refuses at prepare time (fail closed, never a
/// silent history scan), the literal partial predicate keeps the index
/// usable, the bound release equality seeks, and LIMIT 2 keeps duplicate
/// candidate observations (including another authority's) visible so they
/// remain a lookup refusal. The index does not bound custody: the selected
/// candidate is still checked for exact admitted intent, artifact scope and
/// protected source authentication.
const RELEASE_OBSERVATION_CANDIDATE_SQL: &str =
    "SELECT record_key FROM admission_operation_recovery_records
             INDEXED BY idx_recovery_knowledge_join_release
             WHERE record_key GLOB 'knowledge-join:*'
               AND json_extract(payload,'$.release.release')=?1
             LIMIT 2";

/// Data only. The surrounding owner has already anchored the native reader or
/// writer. This lookup never authorizes delivery or replaces current admission.
pub(in crate::admission_operation_store) fn release_observation_source(
    tx: &Connection,
    intent: &ArtifactReleaseIntentV1,
) -> Result<protected::ProtectedSourceReference, AdmissionOperationStoreError> {
    let mut statement = tx
        .prepare(RELEASE_OBSERVATION_CANDIDATE_SQL)
        .map_err(sqlite_error)?;
    let mut rows = statement
        .query([intent.release.as_str()])
        .map_err(sqlite_error)?;
    let key: String = rows
        .next()
        .map_err(sqlite_error)?
        .ok_or_else(|| invalid("release lost its native observation"))?
        .get(0)
        .map_err(sqlite_error)?;
    if rows.next().map_err(sqlite_error)?.is_some() {
        return Err(invalid("release has ambiguous native observations"));
    }
    let (record, _) = load_by_key(tx, &key)?;
    let mut admitted = intent.clone();
    admitted.state = chio_security_types::knowledge::ArtifactDeliveryStateV1::Admitted;
    if record.release != admitted || record.scope != intent.artifact.scope {
        return Err(invalid(
            "release native observation changed its exact intent",
        ));
    }
    protected::source_reference(tx, &key)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// The real compiled records table with the installed release index. This
    /// fixture exercises the exact production candidate query shape only;
    /// custody and refusal semantics stay with the authenticated store tests.
    fn records_fixture(with_release_index: bool) -> Result<Connection, Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(crate::admission_operation_store::recovery::SQL)?;
        if with_release_index {
            connection.execute_batch(include_str!(
                "../../../recovery_knowledge_join_release_index.sql"
            ))?;
        }
        Ok(connection)
    }

    fn insert_join_row(
        connection: &Connection,
        key: &str,
        scope: &str,
        release: &str,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        Ok(connection.execute(
            "INSERT INTO admission_operation_recovery_records
                (record_key,scope_key,kind,version,payload)
             VALUES (?1,?2,'command',1,?3)",
            params![
                key,
                scope,
                serde_json::to_vec(&serde_json::json!({ "release": { "release": release } }))?
            ],
        )?)
    }

    fn candidate_keys(
        connection: &Connection,
        release: &str,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut statement = connection.prepare(RELEASE_OBSERVATION_CANDIDATE_SQL)?;
        let keys = statement
            .query_map([release], |row| row.get::<_, String>(0))?
            .collect::<Result<_, _>>()?;
        Ok(keys)
    }

    #[test]
    fn release_observation_query_plans_through_the_required_index() -> TestResult {
        let connection = records_fixture(true)?;
        insert_join_row(
            &connection,
            "knowledge-join:target:0000000000000001",
            &"0".repeat(64),
            "release-target",
        )?;
        let mut statement = connection.prepare(&format!(
            "EXPLAIN QUERY PLAN {RELEASE_OBSERVATION_CANDIDATE_SQL}"
        ))?;
        let plans: Vec<String> = statement
            .query_map(["release-target"], |row| row.get::<_, String>(3))?
            .collect::<Result<_, _>>()?;
        assert!(!plans.is_empty());
        for plan in &plans {
            assert!(
                plan.contains(
                    "SEARCH admission_operation_recovery_records USING INDEX idx_recovery_knowledge_join_release"
                ),
                "plan must seek the required index: {plan}"
            );
            assert!(!plan.contains("SCAN"), "plan must not scan: {plan}");
            assert!(!plan.contains("TEMP B-TREE"), "plan must not sort: {plan}");
        }
        assert_eq!(
            candidate_keys(&connection, "release-target")?,
            vec!["knowledge-join:target:0000000000000001".to_owned()]
        );
        Ok(())
    }

    #[test]
    fn release_observation_query_stays_bounded_among_unrelated_history() -> TestResult {
        let connection = records_fixture(true)?;
        let scope = "1".repeat(64);
        for sequence in 0..4096_u64 {
            insert_join_row(
                &connection,
                &format!("knowledge-join:other:{sequence:016}"),
                &scope,
                &format!("release-other-{sequence}"),
            )?;
        }
        insert_join_row(
            &connection,
            "knowledge-join:target:0000000000000001",
            &scope,
            "release-target",
        )?;
        let steps = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let counted = std::sync::Arc::clone(&steps);
        connection.progress_handler(
            1,
            Some(move || {
                counted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                false
            }),
        )?;
        let keys = candidate_keys(&connection, "release-target")?;
        connection.progress_handler(0, None::<fn() -> bool>)?;
        assert_eq!(
            keys,
            vec!["knowledge-join:target:0000000000000001".to_owned()]
        );
        let visited = steps.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            visited < 256,
            "an indexed seek must bound VM work over unrelated history; visited {visited} VM steps"
        );
        Ok(())
    }

    #[test]
    fn release_observation_query_refuses_closed_without_the_index() -> TestResult {
        let connection = records_fixture(false)?;
        insert_join_row(
            &connection,
            "knowledge-join:target:0000000000000001",
            &"0".repeat(64),
            "release-target",
        )?;
        assert!(
            candidate_keys(&connection, "release-target").is_err(),
            "an absent release index must refuse instead of scanning"
        );
        Ok(())
    }

    #[test]
    fn release_observation_query_surfaces_duplicates_across_authorities_and_scopes() -> TestResult {
        let connection = records_fixture(true)?;
        insert_join_row(
            &connection,
            "knowledge-join:aaa:0000000000000001",
            &"0".repeat(64),
            "release-target",
        )?;
        insert_join_row(
            &connection,
            "knowledge-join:bbb:0000000000000007",
            &"2".repeat(64),
            "release-target",
        )?;
        insert_join_row(
            &connection,
            "knowledge-join:ccc:0000000000000009",
            &"2".repeat(64),
            "release-other",
        )?;
        let mut duplicates = candidate_keys(&connection, "release-target")?;
        duplicates.sort();
        assert_eq!(
            duplicates,
            vec![
                "knowledge-join:aaa:0000000000000001".to_owned(),
                "knowledge-join:bbb:0000000000000007".to_owned(),
            ],
            "LIMIT 2 must retain both duplicate candidates from other authorities and scopes"
        );
        assert_eq!(
            candidate_keys(&connection, "release-absent")?,
            Vec::<String>::new(),
            "a lost native observation returns no candidate"
        );
        Ok(())
    }
}
