//! Physical replay reads stay inside the existing maintenance byte ceiling.
use super::*;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn compaction_refuses_unowned_nonce_preflight_before_payload_column_access() {
    let initial = chio_test_support::clock::unix_seconds();
    let _time = chio_test_support::clock::scope_unix_secs(initial);
    let fixture = fixture();
    let (operation, outcome) = completed_return(&fixture, "unexpected-nonce-preflight", false)
        .expect("actual signed completed value");
    let original_raw = fixture
        .outcomes
        .load_raw_invocation_by_operation(operation.binding().operation_id())
        .expect("qualified raw read")
        .expect("raw present")
        .canonical_blob()
        .expect("canonical raw");
    assert!(operation.execution_nonce_preflight_digest().is_none());
    let accesses = Arc::new(AtomicUsize::new(0));
    {
        let connection = fixture.outcomes.connection().expect("connection");
        // Fault only this isolated database. No executable budget hold or
        // ownership witness is constructed for this unsupported physical row.
        let foreign_keys: bool = connection
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .expect("foreign key mode");
        connection
            .pragma_update(None, "foreign_keys", false)
            .expect("permit isolated missing hold fixture");
        connection
            .execute(
                "INSERT INTO admission_nonce_preflight_holds
                 (operation_id,budget_operation_id,hold_id,ownership_json,operation_json,recorded_at_unix_ms)
                 VALUES(?1,'unowned-preflight-budget','unowned-preflight-hold',?2,?3,?4)",
                params![
                    operation.binding().operation_id().as_str(),
                    b"{}".as_slice(),
                    vec![b'x'; 262_144],
                    i64::try_from(now_ms()).expect("bounded fixture time")
                ],
            )
            .expect("inject unsupported nonce-preflight custody");
        connection
            .pragma_update(None, "foreign_keys", foreign_keys)
            .expect("restore foreign key mode");
        let observe = accesses.clone();
        connection
            .authorizer(Some(move |context: AuthContext<'_>| {
                if matches!(
                    context.action,
                    AuthAction::Read {
                        table_name: "admission_nonce_preflight_holds",
                        column_name: "ownership_json" | "operation_json"
                    }
                ) {
                    observe.fetch_add(1, Ordering::SeqCst);
                }
                Authorization::Allow
            }))
            .expect("observe unsupported payload columns");
    }
    let _advanced = chio_test_support::clock::scope_unix_secs(initial + 60);
    let now = now_ms();
    let error = fixture
        .outcomes
        .compact_retained_invocation_blobs_page_with_limits(
            now,
            &fixture.fence,
            now,
            None,
            ToolOutcomeCompactionLimits {
                max_payload_bytes: 128 * 1024,
                ..ToolOutcomeCompactionLimits::default()
            },
        )
        .expect_err("unsupported custody must refuse before payload access");
    fixture
        .outcomes
        .connection()
        .expect("connection recovered")
        .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
        .expect("clear observation");
    assert_eq!(accesses.load(Ordering::SeqCst), 0, "{error:?}");
    assert_eq!(
        error,
        ToolOutcomeStoreError::Invariant(
            "retention owner has unexpected sidecar custody; payload bytes and cursor retained"
                .into()
        )
    );
    assert_retained_raw(&fixture, &outcome, original_raw.bytes());
    assert_eq!(fixture.authority.mutation_fence(), fixture.fence);
    remove_fixture_sidecar(
        &fixture,
        "admission_nonce_preflight_holds",
        "admission_nonce_preflight_holds_no_delete",
        operation.binding().operation_id(),
    );
    let resumed = fixture
        .outcomes
        .compact_retained_invocation_blobs_page(now, &fixture.fence, now, None, 64)
        .expect("healthy resume after removing the isolated fault");
    assert_eq!(resumed.compacted, 1);
    assert!(resumed.next_digest.is_none());
}

#[test]
fn compaction_refuses_recovery_status_bytes_before_payload_read() {
    let initial = chio_test_support::clock::unix_seconds();
    let _time = chio_test_support::clock::scope_unix_secs(initial);
    let fixture = fixture();
    let (operation, outcome) = completed_return(&fixture, "recovery-status-byte-screen", false)
        .expect("actual signed completed value");
    let blob = fixture
        .outcomes
        .load_raw_invocation_by_operation(operation.binding().operation_id())
        .expect("raw read")
        .expect("raw present")
        .canonical_blob()
        .expect("canonical raw");
    let _advanced = chio_test_support::clock::scope_unix_secs(initial + 60);
    let now = now_ms();
    let baseline = fixture
        .outcomes
        .compact_retained_invocation_blobs_page_with_limits(
            now,
            &fixture.fence,
            now,
            None,
            ToolOutcomeCompactionLimits::default(),
        )
        .expect("healthy measured replay reads");
    assert_eq!(baseline.compacted, 1);
    let healthy_read_bytes = baseline
        .inspected_payload_bytes
        .checked_add(baseline.inspected_verification_bytes)
        .expect("bounded actual read total");
    let accesses = Arc::new(AtomicUsize::new(0));
    {
        let mut connection = fixture.outcomes.connection().expect("connection");
        let transaction = fixture
            .outcomes
            .begin_write(&mut connection, &fixture.fence, now)
            .expect("begin exact payload rehydration");
        insert_blob_bytes_tx(
            &transaction,
            outcome.raw_output_digest().as_str(),
            blob.bytes(),
            &fixture.fence,
            now,
        )
        .expect("restore original verified raw bytes");
        fixture.outcomes.commit_write(transaction).expect("commit");
        fixture
            .outcomes
            .sync_after_write(&connection)
            .expect("anchor");
        // An uncommitted current component is corruption. Its physical bytes
        // must still be screened before the qualified reader copies them.
        connection
            .execute(
                "INSERT INTO admission_operation_recovery_deferrals
                 (operation_id,canonical_status,status_digest,quarantined,retry_not_before_unix_ms)
                 VALUES(?1,?2,?3,1,?4)",
                params![
                    operation.binding().operation_id().as_str(),
                    vec![b'x'; 4_096],
                    "d".repeat(64),
                    i64::try_from(now + 60_000).expect("bounded fixture retry")
                ],
            )
            .expect("inject fixture-only current component");
        let observe = accesses.clone();
        connection
            .authorizer(Some(move |context: AuthContext<'_>| {
                if matches!(
                    context.action,
                    AuthAction::Read {
                        table_name: "admission_operation_recovery_deferrals",
                        column_name: "canonical_status"
                    }
                ) {
                    observe.fetch_add(1, Ordering::SeqCst);
                }
                Authorization::Allow
            }))
            .expect("observe current-component payload column");
    }
    let error = fixture
        .outcomes
        .compact_retained_invocation_blobs_page_with_limits(
            now,
            &fixture.fence,
            now,
            None,
            ToolOutcomeCompactionLimits {
                // Keep the measured healthy cap. Adding a physical current
                // component must consume extra bytes, before decoding it.
                max_payload_bytes: healthy_read_bytes,
                ..ToolOutcomeCompactionLimits::default()
            },
        )
        .expect_err("current-component reads must obey the same cap");
    fixture
        .outcomes
        .connection()
        .expect("connection recovered")
        .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
        .expect("clear observation");
    assert_eq!(error, ToolOutcomeStoreError::Unavailable(
        "terminal raw payload replay verification exceeds the maintenance payload byte budget; bytes and cursor retained".into()
    ));
    // One prepare access is the metadata length preflight. No subsequent
    // status::load payload statement may be prepared after byte refusal.
    assert_eq!(accesses.load(Ordering::SeqCst), 1);
    assert_retained_raw(&fixture, &outcome, blob.bytes());
    assert_eq!(fixture.authority.mutation_fence(), fixture.fence);
    remove_fixture_sidecar(
        &fixture,
        "admission_operation_recovery_deferrals",
        "admission_operation_recovery_no_delete",
        operation.binding().operation_id(),
    );
    let resumed = fixture
        .outcomes
        .compact_retained_invocation_blobs_page_with_limits(
            now,
            &fixture.fence,
            now,
            None,
            ToolOutcomeCompactionLimits {
                max_payload_bytes: healthy_read_bytes,
                ..ToolOutcomeCompactionLimits::default()
            },
        )
        .expect("same cap and original cursor resume after removing the isolated fault");
    assert_eq!(resumed.compacted, 1);
    assert!(resumed.next_digest.is_none());
}

fn assert_retained_raw(fixture: &Fixture, outcome: &ToolOutcomeRecordV1, original: &[u8]) {
    let connection = fixture.outcomes.connection().expect("usable connection");
    let (size, bytes): (i64, Vec<u8>) = connection
        .query_row(
            "SELECT blob_size_bytes,canonical_bytes FROM tool_outcome_blobs WHERE digest=?1",
            [outcome.raw_output_digest().as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("retained physical raw");
    assert_eq!(bytes, original);
    assert_eq!(
        u64::try_from(size).expect("positive raw size"),
        u64::try_from(original.len()).expect("bounded original size")
    );
    assert_eq!(sha256_hex(&bytes), outcome.raw_output_digest().as_str());
}

fn remove_fixture_sidecar(
    fixture: &Fixture,
    table: &str,
    trigger: &str,
    operation_id: &AdmissionOperationId,
) {
    let connection = fixture.outcomes.connection().expect("connection");
    let definition: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name=?1",
            [trigger],
            |row| row.get(0),
        )
        .expect("isolated fixture trigger");
    connection
        .execute_batch(&format!("DROP TRIGGER {trigger}"))
        .expect("allow only isolated fixture fault removal");
    assert_eq!(
        connection
            .execute(
                &format!("DELETE FROM {table} WHERE operation_id=?1"),
                [operation_id.as_str()]
            )
            .expect("remove only isolated uncommitted sidecar"),
        1
    );
    connection
        .execute_batch(&definition)
        .expect("restore exact guard");
}
