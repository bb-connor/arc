use super::*;

#[test]
fn egress_journal_is_immutable_without_recursive_triggers() -> AnchoredTestResult {
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let pending = pending(&fixture, "egress-immutable", None)?;
    pending.acquire(&fixture)?;
    let before = counts(&fixture)?;
    let connection = fixture.store.connection()?;
    for recursive in [false, true] {
        connection.pragma_update(None, "recursive_triggers", recursive)?;
        for sql in [
            "UPDATE security_participant_egress_events SET observed_at = observed_at + 1",
            "DELETE FROM security_participant_egress_events",
            "INSERT OR REPLACE INTO security_participant_egress_events SELECT * FROM security_participant_egress_events",
            "INSERT OR REPLACE INTO security_participant_egress_events SELECT security_authority_id, sequence + 1, operation_id, phase, tenant_id, request_id, fence_id, canonical_record, event_digest, observed_at FROM security_participant_egress_events",
        ] {
            assert!(connection.execute(sql, []).is_err(), "recursive {recursive}: {sql}");
        }
    }
    native::verify_coverage(&connection)?;
    drop(connection);
    assert_eq!(counts(&fixture)?, before);
    Ok(())
}

#[test]
fn locally_rehashed_egress_history_cannot_replace_anchored_operation_custody() -> AnchoredTestResult
{
    for damage in [
        "acquisition",
        "live_request",
        "commit_time",
        "previous",
        "rows",
        "delete",
    ] {
        let fixture = fixture();
        hydrate(&fixture, &imported(&fixture, "source")?)?;
        let pending = pending(&fixture, "egress-history-damage", None)?;
        let acquired = pending.acquire(&fixture)?;
        pending.commit(&fixture, &commitment(&acquired)?)?;
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
        connection.execute_batch("DROP TRIGGER security_participant_egress_events_no_update; DROP TRIGGER security_participant_egress_events_no_delete;")?;
        if damage == "delete" {
            connection.execute(
                "DELETE FROM security_participant_egress_events WHERE phase = 'committed'",
                [],
            )?;
        } else {
            let bytes: Vec<u8> = connection.query_row("SELECT canonical_record FROM security_participant_egress_events WHERE phase = 'committed'", [], |row| row.get(0))?;
            let mut record: serde_json::Value = serde_json::from_slice(&bytes)?;
            match damage {
                "acquisition" => record["acquisition_digest"] = "0".repeat(64).into(),
                "live_request" => record["live_request_hash"] = "0".repeat(64).into(),
                "commit_time" => {
                    record["command"]["request"]["committed_at_unix_ms"] = 1.into();
                    record["result"]["result"]["committed_at_unix_ms"] = 1.into();
                }
                "previous" => record["previous"] = "0".repeat(64).into(),
                "rows" => record["changes"] = serde_json::json!([]),
                _ => return Err("unrecognized damage fixture".into()),
            }
            let bytes = canonical_json_bytes(&record)?;
            let mut digest_input = b"chio.native-security-egress.commit.v1\0".to_vec();
            digest_input.extend_from_slice(&bytes);
            // Restore canonical local bytes and their unkeyed digest. The
            // independent global anchor and original lease history remain.
            connection.execute("UPDATE security_participant_egress_events SET canonical_record = ?1, event_digest = ?2 WHERE phase = 'committed'", params![bytes, sha256_hex(&digest_input)])?;
        }
        connection.execute_batch(native::egress::sql())?;
        native::egress::verify_catalog(&connection)?;
        assert!(native::verify_coverage(&connection).is_err(), "{damage}");
        drop(connection);
        assert!(
            SqliteAuthorityStore::open_serving(&database, &lock_root).is_err(),
            "{damage}"
        );
    }
    Ok(())
}
