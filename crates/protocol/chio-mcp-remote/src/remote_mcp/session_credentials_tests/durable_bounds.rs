//! Outcome wrapping must not replace a readable pending fence with an oversized row.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::tests::{completed_response, record};
use super::*;

fn request() -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
        "name":"write_file","arguments":{"path":"/workspace/one"},
        "_meta":{"chioRequestId":"bounded-delivery"}}})
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
    response["result"]["padding"] = json!("");
    let overhead = serde_json::to_vec(&response).unwrap().len();
    response["result"]["padding"] = json!("x".repeat(MAX_SESSION_JSON_BYTES - overhead - 1));
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
    response["result"]["numbers"] =
        crate::input::document::<Value>(br#"[0.50,21.0,1e-05,18446744073709551615]"#, 1024)
            .unwrap();
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
