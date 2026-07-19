#[test]
fn generic_second_open_preserves_the_live_dispatch_seal() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("generic-open-preserves-live-seal.sqlite");
    let first = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("open first security state store: {error:?}"));
    seal_live(&first);

    let second = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("open second security state store: {error:?}"));
    let connection = Connection::open(&path)
        .unwrap_or_else(|error| panic!("inspect lifecycle after second open: {error}"));
    let lifecycle: (i64, i64, i64) = connection
        .query_row(
            r#"
            SELECT reconciliation_active, live_dispatch_sealed, compaction_active
            FROM security_declassification_lifecycle WHERE singleton = 1
            "#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap_or_else(|error| panic!("read lifecycle after second open: {error}"));
    assert_eq!(lifecycle, (0, 1, 0));
    let Err(error) = second.begin_declassification_reconciliation() else {
        panic!("generic second open cleared the live dispatch seal");
    };
    assert_eq!(error.kind(), PortErrorKind::Conflict);
    second
        .seal_declassification_live_dispatch()
        .unwrap_or_else(|error| panic!("idempotently confirm preserved live seal: {error:?}"));
}

#[test]
fn active_compaction_fails_readiness_and_blocks_every_lifecycle_transition() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("active-compaction-lifecycle-gates.sqlite");
    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("open security state store: {error:?}"));
    let connection = Connection::open(&path)
        .unwrap_or_else(|error| panic!("open lifecycle mutation connection: {error}"));
    let updated = connection
        .execute(
            r#"
            UPDATE security_declassification_lifecycle
            SET reconciliation_active = 0,
                live_dispatch_sealed = 0,
                compaction_active = 1
            WHERE singleton = 1
            "#,
            [],
        )
        .unwrap_or_else(|error| panic!("activate persisted compaction: {error}"));
    assert_eq!(updated, 1);

    let Err(error) = store.ensure_declassification_evidence_ready() else {
        panic!("active compaction unexpectedly passed readiness");
    };
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    let Err(error) = store.begin_declassification_reconciliation() else {
        panic!("reconciliation began during active compaction");
    };
    assert_eq!(error.kind(), PortErrorKind::Conflict);
    let Err(error) = store.seal_declassification_live_dispatch() else {
        panic!("live dispatch sealed during active compaction");
    };
    assert_eq!(error.kind(), PortErrorKind::Conflict);

    let updated = connection
        .execute(
            r#"
            UPDATE security_declassification_lifecycle
            SET reconciliation_active = 1,
                live_dispatch_sealed = 0,
                compaction_active = 1
            WHERE singleton = 1
            "#,
            [],
        )
        .unwrap_or_else(|error| panic!("seed reconciliation and compaction overlap: {error}"));
    assert_eq!(updated, 1);
    let Err(error) = store.end_declassification_reconciliation() else {
        panic!("reconciliation ended during active compaction");
    };
    assert_eq!(error.kind(), PortErrorKind::Conflict);
}

#[test]
fn readiness_rejects_schema_literal_byte_changes() {
    for (case, object_type, object_name, original, replacement) in [
        (
            "literal-case",
            "table",
            "security_declassification_uses",
            "'released'",
            "'RELEASED'",
        ),
        (
            "literal-whitespace",
            "trigger",
            "security_declassification_use_delete_rejected",
            "'declassification use deletion is rejected'",
            "'declassification use  deletion is rejected'",
        ),
    ] {
        let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = temp.path().join(format!("{case}-tamper.sqlite"));
        let store = SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open security state store: {error:?}"));
        let connection = Connection::open(&path)
            .unwrap_or_else(|error| panic!("open schema tamper connection: {error}"));
        let schema_version: i64 = connection
            .query_row("PRAGMA schema_version", [], |row| row.get(0))
            .unwrap_or_else(|error| panic!("read schema version: {error}"));
        connection
            .execute_batch("PRAGMA writable_schema = ON;")
            .unwrap_or_else(|error| panic!("enable schema tampering: {error}"));
        let changed = connection
            .execute(
                "UPDATE sqlite_schema SET sql = replace(sql, ?1, ?2)
                 WHERE type = ?3 AND name = ?4",
                params![original, replacement, object_type, object_name],
            )
            .unwrap_or_else(|error| panic!("change schema literal bytes: {error}"));
        assert_eq!(changed, 1);
        connection
            .pragma_update(
                None,
                "schema_version",
                schema_version
                    .checked_add(1)
                    .unwrap_or_else(|| panic!("schema version overflow")),
            )
            .unwrap_or_else(|error| panic!("advance schema version: {error}"));
        connection
            .execute_batch("PRAGMA writable_schema = OFF;")
            .unwrap_or_else(|error| panic!("disable schema tampering: {error}"));
        drop(connection);

        let Err(error) = store.ensure_declassification_evidence_ready() else {
            panic!("quoted schema literal byte change unexpectedly passed readiness");
        };
        assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    }
}

#[test]
fn typed_declassification_bindings_separate_live_and_recovery_transitions() {
    let common_tenant = tenant();
    let common_grant = grant();
    let request_hash = Digest32::new([31_u8; 32]);
    let request_id =
        RequestId::new("request-binding").unwrap_or_else(|error| panic!("request id: {error}"));
    let dispatch_commitment_id = record("dispatch-binding");
    let consumption = DeclassificationTransitionBinding::Consumption {
        tenant_id: common_tenant.clone(),
        grant_id: common_grant.clone(),
        request_hash,
        request_id: request_id.clone(),
    };
    let released = DeclassificationTransitionBinding::Released {
        tenant_id: common_tenant.clone(),
        grant_id: common_grant.clone(),
        request_hash,
        request_id: request_id.clone(),
        dispatch_commitment_id: dispatch_commitment_id.clone(),
    };
    let dispatch_failed = DeclassificationTransitionBinding::DispatchFailed {
        tenant_id: common_tenant.clone(),
        grant_id: common_grant.clone(),
        request_hash,
        request_id: request_id.clone(),
        dispatch_commitment_id: dispatch_commitment_id.clone(),
    };
    let live_outcome_unknown = DeclassificationTransitionBinding::OutcomeUnknownAfterDispatch {
        tenant_id: common_tenant.clone(),
        grant_id: common_grant.clone(),
        request_hash,
        request_id,
        dispatch_commitment_id,
    };
    let recovery = DeclassificationTransitionBinding::RecoveryOutcomeUnknown {
        tenant_id: common_tenant,
        grant_id: common_grant,
        request_hash,
        predecessor_evidence_id: OpaqueReceiptRef::new("consumption-evidence")
            .unwrap_or_else(|error| panic!("predecessor evidence id: {error}")),
        predecessor_transition_id: record("consumption-transition"),
    };

    let identities = [
        &consumption,
        &released,
        &dispatch_failed,
        &live_outcome_unknown,
        &recovery,
    ]
        .into_iter()
        .map(|binding| {
            (
                derive_declassification_transition_id(binding)
                    .unwrap_or_else(|error| panic!("derive transition id: {error}")),
                derive_declassification_event_id(binding)
                    .unwrap_or_else(|error| panic!("derive event id: {error}")),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(identities.iter().collect::<BTreeSet<_>>().len(), 5);
    assert!(identities
        .iter()
        .all(|(transition_id, event_id)| transition_id.as_str() != event_id.as_str()));
    assert_eq!(
        recovery.terminal_state(),
        Some(DeclassificationUseState::OutcomeUnknown)
    );
    assert!(!recovery.is_live_dispatch_binding());
    assert!(released.is_live_dispatch_binding());
    assert!(dispatch_failed.is_live_dispatch_binding());
    assert_eq!(
        live_outcome_unknown.terminal_state(),
        Some(DeclassificationUseState::OutcomeUnknown)
    );
    assert!(live_outcome_unknown.is_live_dispatch_binding());
    assert_eq!(
        serde_json::to_value(&live_outcome_unknown)
            .unwrap_or_else(|error| panic!("serialize live unknown binding: {error}"))["kind"],
        "outcome_unknown_after_dispatch"
    );
}
