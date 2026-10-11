//! Retained rows advance maintenance without skipping a byte-deferred owner.
use super::*;
use compaction_fixture::deterministic_completed_return;

#[test]
fn compaction_retained_prefix_resumes_replay_verification_under_same_byte_cap() {
    let initial = 1_700_000_000;
    let _time = chio_test_support::clock::scope_unix_secs(initial);
    let fixture = fixture();
    let (_, stream) = deterministic_completed_return(&fixture, "cursor-stream", true, initial)
        .expect("actual signed stream completion");
    let (operation, value) =
        deterministic_completed_return(&fixture, "cursor-value", false, initial)
            .expect("actual signed value completion");
    assert!(
        stream.raw_output_digest() < value.raw_output_digest(),
        "stable stream digest {} must precede value {}",
        stream.raw_output_digest().as_str(),
        value.raw_output_digest().as_str(),
    );
    let blob = fixture
        .outcomes
        .load_raw_invocation_by_operation(operation.binding().operation_id())
        .expect("qualified raw read")
        .expect("raw present")
        .canonical_blob()
        .expect("canonical raw");
    let predecessor: String = fixture
        .outcomes
        .connection()
        .expect("connection")
        .query_row(
            "SELECT MAX(digest) FROM tool_outcome_blobs WHERE digest < ?1",
            [value.raw_output_digest().as_str()],
            |row| row.get(0),
        )
        .expect("stream guarantees a preceding physical row");
    let predecessor = AdmissionDigest::try_new("predecessor", predecessor).expect("valid digest");
    let _advanced = chio_test_support::clock::scope_unix_secs(initial + 60);
    let now = now_ms();
    let measured = fixture
        .outcomes
        .compact_retained_invocation_blobs_page_with_limits(
            now,
            &fixture.fence,
            now,
            Some(&predecessor),
            ToolOutcomeCompactionLimits {
                max_rows: 1,
                ..ToolOutcomeCompactionLimits::default()
            },
        )
        .expect("measure only the supported value's actual replay reads");
    assert_eq!(measured.compacted, 1);
    let cap = measured.inspected_payload_bytes + measured.inspected_verification_bytes;
    {
        let mut connection = fixture.outcomes.connection().expect("connection");
        let transaction = fixture
            .outcomes
            .begin_write(&mut connection, &fixture.fence, now)
            .expect("begin exact payload rehydration");
        insert_blob_bytes_tx(
            &transaction,
            value.raw_output_digest().as_str(),
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
    }
    let first_row_error = fixture
        .outcomes
        .compact_retained_invocation_blobs_page_with_limits(
            now,
            &fixture.fence,
            now,
            Some(&predecessor),
            ToolOutcomeCompactionLimits {
                max_payload_bytes: cap - 1,
                ..ToolOutcomeCompactionLimits::default()
            },
        )
        .expect_err("an unfit first row has no cursor progress to return");
    assert_eq!(first_row_error, ToolOutcomeStoreError::Unavailable(
        "terminal raw payload replay verification exceeds the maintenance payload byte budget; bytes and cursor retained".into()
    ));
    assert!(blob_state(&fixture, value.raw_output_digest().as_str()).1);
    let stream_size = u64::try_from(blob_state(&fixture, stream.raw_output_digest().as_str()).0)
        .expect("bounded stream raw size");
    assert!(stream_size > 0);
    // Both raw payloads fit. Only the value's subsequent replay verification
    // crosses the unchanged cap, because the unsupported stream consumed bytes.
    assert!(stream_size + u64::try_from(blob.bytes().len()).expect("bounded raw") <= cap);
    let limits = ToolOutcomeCompactionLimits {
        max_payload_bytes: cap,
        ..ToolOutcomeCompactionLimits::default()
    };
    let first = fixture
        .outcomes
        .compact_retained_invocation_blobs_page_with_limits(now, &fixture.fence, now, None, limits)
        .expect("return safe cursor progress even when no payload was erased");
    assert_eq!(first.compacted, 0);
    assert_eq!(first.retained_unsupported, 1);
    assert!(first.byte_budget_exhausted);
    assert!(first.inspected_payload_bytes + first.inspected_verification_bytes <= cap);
    let cursor = first
        .next_digest
        .expect("retained prefix has scan progress");
    assert!(cursor >= *stream.raw_output_digest());
    assert!(
        cursor < *value.raw_output_digest(),
        "deferred owner must be retried"
    );
    assert!(blob_state(&fixture, stream.raw_output_digest().as_str()).1);
    assert!(blob_state(&fixture, value.raw_output_digest().as_str()).1);
    let resumed = fixture
        .outcomes
        .compact_retained_invocation_blobs_page_with_limits(
            now,
            &fixture.fence,
            now,
            Some(&cursor),
            limits,
        )
        .expect("resume after retained prefix under the identical byte cap");
    assert_eq!(resumed.compacted, 1);
    assert!(resumed.inspected_payload_bytes + resumed.inspected_verification_bytes <= cap);
    assert!(!blob_state(&fixture, value.raw_output_digest().as_str()).1);
    assert!(blob_state(&fixture, stream.raw_output_digest().as_str()).1);
    assert!(resumed.next_digest.is_none());
}
