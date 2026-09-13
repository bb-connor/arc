//! Recomputed local hashes cannot replace independently anchored join history.
use super::*;

#[test]
fn canonical_mutation_edits_and_missing_history_cannot_survive_owner_recovery() -> TestResult {
    for damage in ["result", "lease", "previous", "rows", "delete"] {
        let fixture = fixture();
        let source = imported(&fixture, "source")?;
        let initialized = hydrate(&fixture, &source)?;
        let (context, request) = request("native-join")?;
        let (operation, lease) = setup(&fixture, "native-operation", &context)?;
        fixture.store.join_security_participant_flow(
            &operation,
            &lease,
            &initialized,
            &context,
            &request,
            now_ms(),
        )?;
        let Fixture {
            _temp,
            database,
            lock_root,
            authority,
            store,
            ..
        } = fixture;
        drop(store);
        drop(authority);
        let connection = Connection::open(&database)?;
        connection.execute_batch(
            "DROP TRIGGER security_participant_state_mutations_no_update;
             DROP TRIGGER security_participant_state_mutations_no_delete;",
        )?;
        if damage == "delete" {
            connection.execute("DELETE FROM security_participant_state_mutations", [])?;
        } else {
            let bytes: Vec<u8> = connection.query_row(
                "SELECT canonical_record FROM security_participant_state_mutations",
                [],
                |row| row.get(0),
            )?;
            let mut record: serde_json::Value = serde_json::from_slice(&bytes)?;
            match damage {
                "result" => {
                    let generation = record["result"]["context_generation"]
                        .as_u64()
                        .ok_or("recorded generation")?;
                    record["result"]["context_generation"] = (generation + 1).into();
                }
                "lease" => record["lease"]["expires_at"] = record["observed_at"].clone(),
                "previous" => record["previous"] = "0".repeat(64).into(),
                "rows" => record["changes"] = serde_json::json!([]),
                _ => return Err("unrecognized damage fixture".into()),
            }
            let bytes = canonical_json_bytes(&record)?;
            let mut digest_input = b"chio.native-security-mutation.commit.v1\0".to_vec();
            digest_input.extend_from_slice(&bytes);
            // Keep the local artifact canonical and its unkeyed checksum valid.
            // The original operation history and global anchor remain intact.
            connection.execute(
                "UPDATE security_participant_state_mutations
                 SET canonical_record = ?1, mutation_digest = ?2",
                params![bytes, sha256_hex(&digest_input)],
            )?;
        }
        connection.execute_batch(&native::schema::sql()?)?;
        assert!(native::schema::verify_version(&connection, 29)?);
        assert!(native::verify_coverage(&connection).is_err(), "{damage}");
        drop(connection);
        assert!(
            SqliteAuthorityStore::open_serving(&database, &lock_root).is_err(),
            "{damage}"
        );
    }
    Ok(())
}
