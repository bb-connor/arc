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

    struct UnusedTransport;

    impl McpTransport for UnusedTransport {
        fn list_tools(&self) -> Result<Vec<chio_mcp_adapter::edge::McpToolInfo>, AdapterError> {
            Ok(vec![])
        }

        fn call_tool(
            &self,
            _name: &str,
            _arguments: Value,
        ) -> Result<chio_mcp_adapter::edge::McpToolResult, AdapterError> {
            Err(AdapterError::ConnectionFailed(
                "no test dispatch is permitted".into(),
            ))
        }
    }

    #[test]
    fn disconnected_inbox_proves_non_enqueue_and_releases_the_exact_signed_reservation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = chio_test_support::private_tempdir()?;
        let path = directory.path().join("sessions.sqlite3");
        let _lease = crate::tests::acquire_test_session_store(&path);
        let keypair = Keypair::generate();
        let credential = super::super::tests::record();
        let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"write_file","arguments":{},"_meta":{"chioRequestId":"disconnected-inbox"}}});
        let Ok(CallReservation::Pending(pending)) =
            reserve_at(&path, &keypair, &credential, &request, 100)
        else {
            return Err("pending reservation failed".into());
        };
        let (input_tx, input_rx) = mcp_inbox();
        // Admission succeeds first. The receiver then disappears before the
        // owning send, which is the definite failed-send case the HTTP rollback
        // consumes, rather than a decode refusal before call reservation.
        let message = input_tx.account(request.clone())?;
        let (event_tx, _) = broadcast::channel(8);
        let session = RemoteSession::new(RemoteSessionInit {
            clock: RemoteClock::default(),
            session_id: credential.session_id.clone(),
            agent_id: "agent".into(),
            capabilities: vec![],
            issued_capabilities: vec![],
            auth_context: SessionAuthContext::streamable_http_static_bearer("agent", "token", None),
            auth_mode_fingerprint: "auth".into(),
            policy_fingerprint: "policy".into(),
            runtime_contract_fingerprint: "runtime".into(),
            hosted_isolation: RemoteHostedIsolationMode::DedicatedPerSession,
            lifecycle_policy: SessionLifecyclePolicy {
                idle_expiry_millis: DEFAULT_SESSION_IDLE_EXPIRY_MILLIS,
                drain_grace_millis: DEFAULT_SESSION_DRAIN_GRACE_MILLIS,
                reaper_interval_millis: DEFAULT_SESSION_REAPER_INTERVAL_MILLIS,
                tombstone_retention_millis: DEFAULT_SESSION_TOMBSTONE_RETENTION_MILLIS,
            },
            protocol_version: None,
            peer_capabilities: None,
            initialize_params: None,
            lifecycle_snapshot: None,
            input_tx: input_tx.clone(),
            event_tx,
            retained_notification_events: Arc::new(StdMutex::new(VecDeque::new())),
            next_event_id: Arc::new(AtomicU64::new(0)),
            session_db_path: None,
            approval_redemption: None,
            session_store_lease: None,
            resume_hmac_keyring: None,
            resume_generation: 0,
            upstream_transport: Arc::new(UnusedTransport),
        })?;
        session.mark_ready(
            Some("2025-11-25".into()),
            json!({}),
            PeerCapabilities::default(),
        )?;
        drop(input_rx);
        let Err(proof) = session.send_accounted(message) else {
            return Err("disconnected inbox accepted a request".into());
        };
        assert!(matches!(
            proof.into_error(),
            CliError::Adapter(AdapterError::ConnectionFailed(_))
        ));
        rollback_at(&path, &keypair, &pending).map_err(|_| "definite failed-send rollback")?;
        assert_eq!(
            input_tx.usage()?,
            chio_mcp_adapter::edge::ingress::IngressUsage::default()
        );
        let conn = open_db(&path)?;
        assert!(read_latch(&conn, &keypair, &credential.session_id)
            .map_err(|_| "read rolled-back latch")?
            .is_none());
        assert!(matches!(
            reserve_at(&path, &keypair, &credential, &request, 100),
            Ok(CallReservation::Pending(_))
        ));
        Ok(())
    }

    #[test]
    fn legacy_signed_row_without_reservation_id_preserves_its_canonical_bytes_and_fence(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = chio_test_support::private_tempdir()?;
        let path = directory.path().join("sessions.sqlite3");
        let _lease = crate::tests::acquire_test_session_store(&path);
        let keypair = Keypair::generate();
        let credential = super::super::tests::record();
        let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"write_file","arguments":{},"_meta":{"chioRequestId":"legacy-pending"}}});
        let Ok(CallReservation::Pending(pending)) =
            reserve_at(&path, &keypair, &credential, &request, 100)
        else {
            return Err("pending reservation failed".into());
        };
        // Sign the historical JSON shape itself, which has no new field. This
        // is retained signed data, not a new-type signature accepted by fiat.
        let mut legacy_body = serde_json::to_value(&pending)?;
        legacy_body
            .as_object_mut()
            .ok_or("legacy call object")?
            .remove("reservationId");
        let encoded = serde_json::to_string(&legacy_body)?;
        let (signature, legacy_bytes) = keypair.sign_canonical(&legacy_body)?;
        let conn = open_db(&path)?;
        for table in [CALL_TABLE, LATCH_TABLE] {
            conn.execute(
                &format!("UPDATE {table} SET record_json=?1,signature=?2 WHERE session_id=?3 AND request_id=?4"),
                params![encoded, signature.to_hex(), pending.session_id, pending.request_id],
            )?;
        }
        let reopened = read_latch(&conn, &keypair, &credential.session_id)
            .map_err(|_| "legacy signed latch read")?
            .ok_or("legacy signed latch missing")?;
        assert!(reopened.reservation_id.is_none());
        assert_eq!(canonical_json_bytes(&reopened)?, legacy_bytes);
        assert!(keypair
            .public_key()
            .verify(&canonical_json_bytes(&reopened)?, &signature));
        assert!(!input::encode_session(&reopened)?.contains("reservationId"));
        assert!(rollback_at(&path, &keypair, &reopened).is_err());
        let retained: (String, String) = conn.query_row(
            &format!("SELECT record_json,signature FROM {LATCH_TABLE} WHERE session_id=?1"),
            [&credential.session_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(retained, (encoded, signature.to_hex()));
        assert!(reserve_at(&path, &keypair, &credential, &request, 100).is_err());
        Ok(())
    }

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
