//! Reverse only the exact signed pending reservation of a definite non-enqueue.

use super::*;

pub(crate) fn rollback_not_enqueued_call(
    state: &RemoteAppState,
    pending: &CredentialCall,
    _proof: &session_core_session::NotEnqueued,
) -> Result<(), Response> {
    let (path, keypair) = operator_runtime(state)?;
    rollback_at(path, &keypair, pending)
}

fn rollback_at(path: &FsPath, keypair: &Keypair, pending: &CredentialCall) -> Result<(), Response> {
    if pending.state != "pending" || pending.reservation_id.is_none() {
        return Err(fence_error());
    }
    let mut conn = open_db(path).map_err(storage_error)?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(storage_error)?;
    let current = read_latch(&tx, keypair, &pending.session_id)?.ok_or_else(fence_error)?;
    if current != *pending {
        return Err(fence_error());
    }
    let row: Option<(String, String)> = tx
        .query_row(
            &format!("SELECT record_json,signature FROM {CALL_TABLE} WHERE session_id=?1 AND request_id=?2"),
            params![pending.session_id, pending.request_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(storage_error)?;
    let (encoded, signature) = row.ok_or_else(fence_error)?;
    let retained = decode_call(
        keypair,
        &pending.session_id,
        &pending.request_id,
        &encoded,
        &signature,
    )?;
    if retained != *pending {
        return Err(fence_error());
    }
    // Both signed identities, including the random reservation instance, match
    // inside one write transaction. A later or rebound latch cannot be erased.
    let deleted_call = tx
        .execute(
            &format!("DELETE FROM {CALL_TABLE} WHERE session_id=?1 AND request_id=?2"),
            params![pending.session_id, pending.request_id],
        )
        .map_err(storage_error)?;
    let deleted_latch = tx
        .execute(
            &format!("DELETE FROM {LATCH_TABLE} WHERE session_id=?1 AND request_id=?2"),
            params![pending.session_id, pending.request_id],
        )
        .map_err(storage_error)?;
    if deleted_call != 1 || deleted_latch != 1 {
        return Err(fence_error());
    }
    tx.commit().map_err(storage_error)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn stale_refusal_cannot_remove_a_rebound_reservation_with_identical_request_bytes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = chio_test_support::private_tempdir()?;
        let path = directory.path().join("sessions.sqlite3");
        let _lease = crate::tests::acquire_test_session_store(&path);
        let keypair = Keypair::generate();
        let credential = super::super::tests::record();
        let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"write_file","arguments":{},"_meta":{"chioRequestId":"same-logical-call"}}});
        let Ok(CallReservation::Pending(original)) =
            reserve_at(&path, &keypair, &credential, &request, 100)
        else {
            return Err("original reservation failed".into());
        };
        rollback_at(&path, &keypair, &original).map_err(|_| "exact rollback failed")?;
        let Ok(CallReservation::Pending(rebound)) =
            reserve_at(&path, &keypair, &credential, &request, 100)
        else {
            return Err("rebound reservation failed".into());
        };
        assert_ne!(original.reservation_id, rebound.reservation_id);
        assert!(rollback_at(&path, &keypair, &original).is_err());
        let conn = open_db(&path)?;
        let retained = read_latch(&conn, &keypair, &credential.session_id)
            .map_err(|_| "read rebound latch")?
            .ok_or("rebound latch disappeared")?;
        assert_eq!(retained.reservation_id, rebound.reservation_id);
        assert_eq!(retained.state, "pending");
        assert!(reserve_at(&path, &keypair, &credential, &request, 100).is_err());
        Ok(())
    }

    #[test]
    fn uncertain_or_completed_outcome_cannot_be_rolled_back_as_a_non_enqueue(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for state in ["fenced", "completed_unacknowledged"] {
            let directory = chio_test_support::private_tempdir()?;
            let path = directory.path().join("sessions.sqlite3");
            let _lease = crate::tests::acquire_test_session_store(&path);
            let keypair = Keypair::generate();
            let credential = super::super::tests::record();
            let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
                "name":"write_file","arguments":{},"_meta":{"chioRequestId":"retained-outcome"}}});
            let Ok(CallReservation::Pending(pending)) =
                reserve_at(&path, &keypair, &credential, &request, 100)
            else {
                return Err("pending reservation failed".into());
            };
            let mut terminal = (*pending).clone();
            terminal.state = state.into();
            terminal.response = Some(json!({"jsonrpc":"2.0","id":1,
                "error":{"code":-32603,"message":"retained effect outcome"}}));
            let conn = open_db(&path)?;
            write_call(&conn, &keypair, &terminal).map_err(|_| "retain outcome")?;
            assert!(rollback_at(&path, &keypair, &pending).is_err());
            let retained = read_latch(&conn, &keypair, &credential.session_id)
                .map_err(|_| "read retained latch")?
                .ok_or("retained outcome disappeared")?;
            assert_eq!(retained.state, state);
            assert_eq!(retained.response, terminal.response);
            let mut next = request.clone();
            next["params"]["_meta"]["chioRequestId"] = json!("later-call");
            assert!(reserve_at(&path, &keypair, &credential, &next, 100).is_err());
        }
        Ok(())
    }
}
