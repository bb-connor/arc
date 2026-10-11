//! Outcome wrapping must not replace a readable pending fence with a row the
//! native reader cannot reopen.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::tests::{completed_response, record};
use super::*;
use chio_core::canonical::UntrustedJsonError;
use chio_core::receipt::body::ChioReceipt;
use std::error::Error as _;

const DEPTH_SEARCH_LIMIT: usize = 128;

fn request() -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
        "name":"write_file","arguments":{"path":"/workspace/one"},
        "_meta":{"chioRequestId":"bounded-delivery"}}})
}

fn nested_decimal(depth: usize) -> Value {
    (0..depth).fold(json!(0.5), |inner, _| Value::Array(vec![inner]))
}

fn decimal_leaf(mut value: &Value, depth: usize) -> Option<f64> {
    for _ in 0..depth {
        value = value.as_array()?.first()?;
    }
    value.as_f64()
}

/// Mirror a nested decimal tool output into the MCP result and its signed evidence.
fn nested_event(keypair: &Keypair, completed: &Value, depth: usize) -> (Value, Value) {
    let output =
        json!({"content": [], "structuredContent": nested_decimal(depth), "isError": false});
    let signed: ChioReceipt =
        serde_json::from_value(completed["result"]["_meta"]["chioEvidence"]["receipt"].clone())
            .unwrap();
    let mut body = signed.body();
    body.content_hash = sha256_hex(&canonical_json_bytes(&output).unwrap());
    let receipt = ChioReceipt::sign(body, keypair).unwrap();
    let mut event = completed.clone();
    event["result"]["content"] = output["content"].clone();
    event["result"]["structuredContent"] = output["structuredContent"].clone();
    event["result"]["isError"] = output["isError"].clone();
    event["result"]["_meta"]["chioEvidence"]["receipt"] = serde_json::to_value(&receipt).unwrap();
    event["result"]["_meta"]["chioEvidence"]["output"] = output.clone();
    (event, output)
}

/// Extend the genuinely signed output and mirror the adapter's MCP-shaped
/// projection. Receipt identity, capability, request and admission checks remain.
fn signed_extension(keypair: &Keypair, completed: &Value, field: &str, value: Value) -> Value {
    let signed: ChioReceipt =
        serde_json::from_value(completed["result"]["_meta"]["chioEvidence"]["receipt"].clone())
            .unwrap();
    assert_eq!(signed.kernel_key, keypair.public_key());
    assert!(signed.verify_signature().unwrap());
    let mut output = completed["result"]["_meta"]["chioEvidence"]["output"].clone();
    assert!(output["content"].is_array() && output["isError"].is_boolean());
    output[field] = value;
    let mut body = signed.body();
    body.content_hash = sha256_hex(&canonical_json_bytes(&output).unwrap());
    let receipt = ChioReceipt::sign(body, keypair).unwrap();
    let mut event = completed.clone();
    // The existing value_to_tool_result branch clones an MCP-shaped object.
    // These fixtures already contain content and isError, so no defaults or
    // synthesized content are needed for that exact canonical projection.
    event["result"] = output.clone();
    event["result"]["_meta"] = completed["result"]["_meta"].clone();
    event["result"]["_meta"]["chioEvidence"]["receipt"] = serde_json::to_value(receipt).unwrap();
    event["result"]["_meta"]["chioEvidence"]["output"] = output;
    event
}

/// The terminal row `finish_at` would persist for a verified completed event.
fn wrapped_completion(pending: &CredentialCall, event: &Value) -> CredentialCall {
    let signed: ChioReceipt =
        serde_json::from_value(event["result"]["_meta"]["chioEvidence"]["receipt"].clone())
            .unwrap();
    let delivery = DeliveryAcknowledgement {
        schema: DELIVERY_SCHEMA.to_owned(),
        request_id: pending.request_id.clone(),
        request_hash: pending.request_hash.clone(),
        receipt_id: signed.id,
        result_hash: signed.content_hash,
        acknowledgement: URL_SAFE_NO_PAD.encode(Keypair::generate().seed_bytes()),
    };
    let mut response = event.clone();
    response["result"]["_meta"]["chioDelivery"] = serde_json::to_value(&delivery).unwrap();
    let mut terminal = pending.clone();
    terminal.delivery_ack = Some(delivery);
    terminal.state = "completed_unacknowledged".to_owned();
    terminal.response = Some(response);
    terminal
}

fn native_read(encoded: &[u8]) -> Result<Value, UntrustedJsonError> {
    crate::input::decode::<Value>(encoded, MAX_SESSION_JSON_BYTES)
}

/// Deepest candidate the unchanged native session reader accepts. The next
/// deeper candidate must be refused for nesting depth.
fn deepest_readable(encode: impl Fn(usize) -> Vec<u8>) -> usize {
    let deepest = (0..=DEPTH_SEARCH_LIMIT)
        .take_while(|depth| native_read(&encode(*depth)).is_ok())
        .last()
        .expect("the shallowest candidate must be readable");
    assert!(
        deepest < DEPTH_SEARCH_LIMIT,
        "the native reader must refuse some depth within the search range"
    );
    let refusal = native_read(&encode(deepest + 1)).expect_err("next depth must be refused");
    assert!(matches!(refusal, UntrustedJsonError::SignedInput(_)));
    assert!(refusal
        .source()
        .expect("parser cause")
        .to_string()
        .contains("recursion limit exceeded"));
    deepest
}

type StoredRow = (String, String, String);

fn persisted_rows(path: &FsPath, session_id: &str, request_id: &str) -> (StoredRow, StoredRow) {
    let connection = open_db(path).unwrap();
    let call = connection
        .query_row(
            &format!(
                "SELECT request_id,record_json,signature FROM {CALL_TABLE}
                 WHERE session_id=?1 AND request_id=?2"
            ),
            params![session_id, request_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let latch = connection
        .query_row(
            &format!(
                "SELECT request_id,record_json,signature FROM {LATCH_TABLE} WHERE session_id=?1"
            ),
            params![session_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let calls: i64 = connection
        .query_row(&format!("SELECT COUNT(*) FROM {CALL_TABLE}"), [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(calls, 1);
    (call, latch)
}

#[cfg(target_os = "linux")]
#[test]
fn delivery_writer_refuses_unreadable_depth_before_replacing_pending_rows() {
    let directory = chio_test_support::private_tempdir().unwrap();
    let path = directory.path().join("sessions.sqlite3");
    let _lease = crate::tests::acquire_test_session_store(&path);
    let keypair = Keypair::generate();
    let credential = record();
    let request = request();
    let Ok(CallReservation::Pending(pending)) =
        reserve_at(&path, &keypair, &credential, &request, unix_now())
    else {
        panic!("pending reservation required");
    };
    let completed = completed_response(
        &keypair,
        &pending,
        request["params"]["arguments"].clone(),
        false,
    )
    .unwrap();
    let depth = deepest_readable(|depth| {
        serde_json::to_vec(&nested_event(&keypair, &completed, depth).0).unwrap()
    });
    let (event, output) = nested_event(&keypair, &completed, depth);
    let encoded = serde_json::to_vec(&event).unwrap();
    native_read(&encoded).expect("the projected event is readable");
    assert!(
        encoded.len() < 64 * 1024,
        "the depth fixture stays far below the 4 MiB child and 8 MiB row limits"
    );
    assert_eq!(decimal_leaf(&output["structuredContent"], depth), Some(0.5));
    assert!(verified_completed_response(&keypair, &pending, &event));

    let rows_before = persisted_rows(&path, &credential.session_id, &pending.request_id);
    let pending_before = serde_json::to_value(&*pending).unwrap();
    let refusal = match finish_at(&path, &keypair, &pending, &event) {
        Ok(_) => panic!(
            "delivery wrapper committed a row the native reader cannot reopen \
             (structuredContent depth {depth})"
        ),
        Err(refusal) => refusal,
    };
    assert_eq!(refusal.status(), StatusCode::SERVICE_UNAVAILABLE);
    let cause = refusal
        .extensions()
        .get::<std::sync::Arc<UntrustedJsonError>>()
        .expect("typed native reader cause");
    assert!(matches!(**cause, UntrustedJsonError::SignedInput(_)));

    let rows_after = persisted_rows(&path, &credential.session_id, &pending.request_id);
    assert_eq!(rows_after, rows_before);
    assert_eq!(serde_json::to_value(&*pending).unwrap(), pending_before);
    let connection = open_db(&path).unwrap();
    let latch = read_latch(&connection, &keypair, &credential.session_id)
        .unwrap()
        .unwrap();
    let (call_row, _) = &rows_after;
    let call = decode_call(
        &keypair,
        &credential.session_id,
        &pending.request_id,
        &call_row.1,
        &call_row.2,
    )
    .unwrap();
    for retained in [&latch, &call] {
        assert_eq!(serde_json::to_value(retained).unwrap(), pending_before);
        assert_eq!(retained.state, "pending");
        assert_eq!(retained.request_hash, pending.request_hash);
        assert!(retained.response.is_none());
        assert!(retained.delivery_ack.is_none());
    }
    drop(connection);
    let mut other = request.clone();
    other["params"]["_meta"]["chioRequestId"] = json!("bounded-delivery-next");
    let Err(fenced) = reserve_at(&path, &keypair, &credential, &other, unix_now()) else {
        panic!("a different request must remain fenced by the pending call");
    };
    assert_eq!(fenced.status(), StatusCode::CONFLICT);
    assert!(fenced
        .extensions()
        .get::<std::sync::Arc<UntrustedJsonError>>()
        .is_none());
    assert_eq!(
        persisted_rows(&path, &credential.session_id, &pending.request_id),
        rows_before
    );
}

#[cfg(target_os = "linux")]
#[test]
fn delivery_writer_accepts_deepest_readable_row_with_decimal_output() {
    let directory = chio_test_support::private_tempdir().unwrap();
    let path = directory.path().join("sessions.sqlite3");
    let _lease = crate::tests::acquire_test_session_store(&path);
    let keypair = Keypair::generate();
    let credential = record();
    let request = request();
    let Ok(CallReservation::Pending(pending)) =
        reserve_at(&path, &keypair, &credential, &request, unix_now())
    else {
        panic!("pending reservation required");
    };
    let completed = completed_response(
        &keypair,
        &pending,
        request["params"]["arguments"].clone(),
        false,
    )
    .unwrap();
    let depth = deepest_readable(|depth| {
        let (event, _) = nested_event(&keypair, &completed, depth);
        serde_json::to_vec(&wrapped_completion(&pending, &event)).unwrap()
    });
    let (event, output) = nested_event(&keypair, &completed, depth);
    assert!(verified_completed_response(&keypair, &pending, &event));
    let delivered = finish_at(&path, &keypair, &pending, &event)
        .unwrap_or_else(|_| panic!("persist the deepest readable completed delivery"));

    let connection = open_db(&path).unwrap();
    let retained = read_latch(&connection, &keypair, &credential.session_id)
        .unwrap()
        .unwrap();
    let (call_row, _) = persisted_rows(&path, &credential.session_id, &pending.request_id);
    let call = decode_call(
        &keypair,
        &credential.session_id,
        &pending.request_id,
        &call_row.1,
        &call_row.2,
    )
    .unwrap();
    for reopened in [&retained, &call] {
        assert_eq!(reopened.state, "completed_unacknowledged");
        let response = reopened.response.as_ref().unwrap();
        assert_eq!(response, &delivered);
        assert_eq!(
            response["result"]["_meta"]["chioEvidence"]["output"],
            output
        );
        assert_eq!(
            response["result"]["structuredContent"],
            output["structuredContent"]
        );
        assert_eq!(
            decimal_leaf(&response["result"]["structuredContent"], depth),
            Some(0.5)
        );
    }
    drop(connection);
    let Ok(CallReservation::Replay(replayed)) =
        reserve_at(&path, &keypair, &credential, &request, unix_now())
    else {
        panic!("reopen must replay the deepest readable completed response");
    };
    assert_eq!(replayed, delivered);
    let acknowledgement =
        serde_json::from_value(delivered["result"]["_meta"]["chioDelivery"].clone()).unwrap();
    acknowledge_at(&path, &keypair, &credential, &acknowledgement)
        .unwrap_or_else(|_| panic!("acknowledge persisted delivery"));
    let connection = open_db(&path).unwrap();
    let acknowledged = read_latch(&connection, &keypair, &credential.session_id)
        .unwrap()
        .unwrap();
    assert_eq!(acknowledged.state, "acknowledged");
    drop(connection);
    let mut next = request.clone();
    next["params"]["_meta"]["chioRequestId"] = json!("bounded-delivery-next");
    assert!(matches!(
        reserve_at(&path, &keypair, &credential, &next, unix_now()),
        Ok(CallReservation::Pending(_))
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn delivery_writer_refuses_event_sized_outcome_before_replacing_pending_rows() {
    let directory = chio_test_support::private_tempdir().unwrap();
    let path = directory.path().join("sessions.sqlite3");
    let _lease = crate::tests::acquire_test_session_store(&path);
    let keypair = Keypair::generate();
    let credential = record();
    let request = request();
    let Ok(CallReservation::Pending(pending)) =
        reserve_at(&path, &keypair, &credential, &request, unix_now())
    else {
        panic!("pending reservation required");
    };
    let mut response = completed_response(
        &keypair,
        &pending,
        request["params"]["arguments"].clone(),
        false,
    )
    .unwrap();
    response["result"]["_meta"]["chioEvidence"]["fixtureAlignment"] = json!(false);
    let empty = signed_extension(&keypair, &response, "padding", json!(""));
    let mut remaining = MAX_SESSION_JSON_BYTES - serde_json::to_vec(&empty).unwrap().len() - 1;
    if !remaining.is_multiple_of(2) {
        // Only a diagnostic boolean changes by one byte. Signed padding has two
        // copies, and the exact original input ceiling remains unchanged.
        response["result"]["_meta"]["chioEvidence"]["fixtureAlignment"] = json!(true);
        remaining += 1;
    }
    response = signed_extension(
        &keypair,
        &response,
        "padding",
        json!("x".repeat(remaining / 2)),
    );
    assert_eq!(
        serde_json::to_vec(&response).unwrap().len(),
        MAX_SESSION_JSON_BYTES - 1
    );
    assert!(verified_completed_response(&keypair, &pending, &response));
    assert!(
        finish_at(&path, &keypair, &pending, &response).is_err(),
        "delivery wrapper committed a row beyond the strict reopen limit"
    );
    let connection = open_db(&path).unwrap();
    let retained = read_latch(&connection, &keypair, &credential.session_id)
        .unwrap()
        .unwrap();
    assert_eq!(retained.state, "pending");
    assert_eq!(retained.request_hash, pending.request_hash);
    let encoded: String = connection
        .query_row(
            &format!("SELECT record_json FROM {CALL_TABLE} WHERE session_id=?1 AND request_id=?2"),
            params![credential.session_id, pending.request_id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(encoded.len() <= MAX_SESSION_JSON_BYTES);
    assert!(retained.response.is_none());
}

#[cfg(target_os = "linux")]
#[test]
fn delivery_writer_preserves_decoded_decimal_native_replay_and_acknowledgement() {
    let directory = chio_test_support::private_tempdir().unwrap();
    let path = directory.path().join("sessions.sqlite3");
    let _lease = crate::tests::acquire_test_session_store(&path);
    let keypair = Keypair::generate();
    let credential = record();
    let request = request();
    let Ok(CallReservation::Pending(pending)) =
        reserve_at(&path, &keypair, &credential, &request, unix_now())
    else {
        panic!("pending reservation required");
    };
    let mut response = completed_response(
        &keypair,
        &pending,
        request["params"]["arguments"].clone(),
        false,
    )
    .unwrap();
    response = signed_extension(
        &keypair,
        &response,
        "numbers",
        crate::input::document::<Value>(br#"[0.50,21.0,1e-05,18446744073709551615]"#, 1024)
            .unwrap(),
    );
    let delivered = finish_at(&path, &keypair, &pending, &response)
        .unwrap_or_else(|_| panic!("persist completed delivery"));
    let connection = open_db(&path).unwrap();
    let retained = read_latch(&connection, &keypair, &credential.session_id)
        .unwrap()
        .unwrap();
    assert_eq!(retained.state, "completed_unacknowledged");
    assert_eq!(
        retained.response.as_ref().unwrap()["result"]["numbers"],
        delivered["result"]["numbers"]
    );
    drop(connection);
    let Ok(CallReservation::Replay(replayed)) =
        reserve_at(&path, &keypair, &credential, &request, unix_now())
    else {
        panic!("reopen must replay the original native numeric response");
    };
    assert_eq!(replayed, delivered);
    assert_eq!(replayed["result"]["numbers"][3].as_u64(), Some(u64::MAX));
    let acknowledgement =
        serde_json::from_value(delivered["result"]["_meta"]["chioDelivery"].clone()).unwrap();
    acknowledge_at(&path, &keypair, &credential, &acknowledgement)
        .unwrap_or_else(|_| panic!("acknowledge persisted delivery"));
}
