//! The caller's private context is an anchored nonce participant, not a permit.

use super::*;
use chio_kernel::admission_operation::AdmissionCallerDispatchContextV1;
use chio_kernel::receipt_store::AdmissionCallerDispatchCapture;

const PAYLOAD: &[u8] =
    br#"{"schema":"chio.kernel-caller-context-test.v1","value":"private-context"}"#;

fn ready() -> TestResult<NonceFixture> {
    ready_with_transport("caller-report:test-server")
}

fn pending() -> TestResult<NonceFixture> {
    pending_with_transport("caller-report:test-server")
}

fn pending_with_transport(transport: &str) -> TestResult<NonceFixture> {
    let mut fixture = ready_with_transport(transport)?;
    let command = nonce_command(
        &fixture.fixture.store,
        &fixture.fixture.fence,
        &fixture.operation,
        &fixture.key,
        Vec::new(),
        AdmissionOperationState::CapturePending,
    )?;
    fixture.operation = fixture
        .fixture
        .store
        .begin_execution_nonce_capture(&command, now_ms())?
        .into_operation();
    Ok(fixture)
}

fn ready_with_transport(transport: &str) -> TestResult<NonceFixture> {
    let mut fixture = advance_nonce_fixture_with_transport(
        prepared_nonce_fixture(None)?,
        true,
        None,
        true,
        Some(transport),
    )?;
    fixture.operation = fixture
        .fixture
        .store
        .reserve_execution_nonce_and_commit_admission(
            &reserve_command(&fixture)?,
            &fixture.reservation,
            now_ms(),
        )?
        .into_operation();
    Ok(fixture)
}

fn context(fixture: &NonceFixture) -> TestResult<AdmissionCallerDispatchContextV1> {
    Ok(AdmissionCallerDispatchContextV1::prepare(
        &fixture.operation,
        &fixture.original,
        PAYLOAD,
    )?)
}

fn command(
    fixture: &NonceFixture,
    context: &AdmissionCallerDispatchContextV1,
) -> TestResult<AdmissionOperationCommand> {
    nonce_command(
        &fixture.fixture.store,
        &fixture.fixture.fence,
        &fixture.operation,
        &fixture.key,
        vec![AdmissionAttachment::CallerDispatchContextDigest(
            context.digest().clone(),
        )],
        AdmissionOperationState::DispatchCommitted,
    )
}

fn capture(fixture: &mut NonceFixture, context: &AdmissionCallerDispatchContextV1) -> TestResult {
    let command = command(fixture, context)?;
    fixture.operation = fixture
        .fixture
        .store
        .capture_caller_invocation_and_commit_dispatch(AdmissionCallerDispatchCapture {
            operation: &fixture.operation,
            recovery_lease: command.recovery_lease(),
            request: lifecycle::capture_request(fixture),
            context,
            active_fence: &fixture.fixture.fence,
            trusted_now_unix_ms: now_ms(),
        })?
        .operation;
    Ok(())
}

fn load(fixture: &NonceFixture) -> TestResult<AdmissionCallerDispatchContextV1> {
    fixture
        .fixture
        .store
        .load_caller_dispatch_context(
            fixture.operation.binding().operation_id(),
            &fixture.fixture.fence,
            now_ms(),
        )?
        .ok_or("retained caller context missing".into())
}

#[test]
fn caller_context_commits_with_capture_and_survives_restart() -> TestResult {
    let mut fixture = pending()?;
    let context = context(&fixture)?;
    let pending_version = fixture.operation.version();
    capture(&mut fixture, &context)?;
    assert_eq!(fixture.operation.version(), pending_version + 1);
    assert_eq!(lifecycle::state(&fixture)?, ("captured".into(), 2, 1));
    assert_eq!(load(&fixture)?.canonical_bytes(), context.canonical_bytes());
    assert_eq!(load(&fixture)?.kernel_context_json(), PAYLOAD);
    assert_eq!(
        fixture.operation.state(),
        AdmissionOperationState::DispatchCommitted
    );
    assert_eq!(load(&fixture)?.canonical_bytes(), context.canonical_bytes());
    let fixture = lifecycle::reopen(fixture)?;
    assert_eq!(load(&fixture)?.canonical_bytes(), context.canonical_bytes());
    Ok(())
}

#[test]
fn caller_context_capture_replays_exactly_and_rejects_generic_commands() -> TestResult {
    let mut fixture = pending()?;
    let context = context(&fixture)?;
    let command = command(&fixture, &context)?;
    assert!(fixture
        .fixture
        .store
        .compare_and_swap(&command, now_ms())
        .is_err());
    assert!(fixture
        .fixture
        .store
        .begin_execution_nonce_capture(&command, now_ms())
        .is_err());
    let pending = fixture.operation.clone();
    capture(&mut fixture, &context)?;
    let committed = fixture.operation.clone();
    let replay = fixture
        .fixture
        .store
        .capture_caller_invocation_and_commit_dispatch(AdmissionCallerDispatchCapture {
            operation: &pending,
            recovery_lease: command.recovery_lease(),
            request: lifecycle::capture_request(&fixture),
            context: &context,
            active_fence: &fixture.fixture.fence,
            trusted_now_unix_ms: now_ms(),
        })?;
    assert_eq!(replay.operation, committed);
    assert!(matches!(
        replay.decision,
        chio_kernel::budget_store::BudgetInvocationCaptureDecision::AlreadyCaptured(_)
    ));
    assert!(
        fixture
            .fixture
            .store
            .capture_invocation_and_commit_dispatch(
                &pending,
                command.recovery_lease(),
                lifecycle::capture_request(&fixture),
                &fixture.fixture.fence,
                now_ms(),
            )
            .is_err(),
        "generic replay cannot omit the committed context"
    );
    assert_eq!(load(&fixture)?.canonical_bytes(), context.canonical_bytes());
    Ok(())
}

#[test]
fn caller_context_rejects_substituted_binding_and_noncanonical_payloads() -> TestResult {
    let fixture = pending()?;
    for bytes in [
        b"{} ".as_slice(),
        b"[]",
        b"{\"a\":1,\"a\":1}",
        b"{\"b\":1,\"a\":2}",
    ] {
        assert!(AdmissionCallerDispatchContextV1::prepare(
            &fixture.operation,
            &fixture.original,
            bytes
        )
        .is_err());
    }
    let oversized = vec![b' '; 524_289];
    assert!(AdmissionCallerDispatchContextV1::prepare(
        &fixture.operation,
        &fixture.original,
        &oversized
    )
    .is_err());
    let context = context(&fixture)?;
    assert!(!format!("{context:?}").contains("private-context"));
    let wire: serde_json::Value = serde_json::from_slice(context.canonical_bytes())?;
    for (field, value) in [
        ("schema", serde_json::json!("other")),
        ("operation_id", serde_json::json!("a".repeat(64))),
        ("request_binding_hash", serde_json::json!("b".repeat(64))),
        ("capture_pending_operation_version", serde_json::json!(0)),
        ("execution_nonce_id", serde_json::json!("other-nonce")),
        ("budget_hold_id", serde_json::json!("other-hold")),
        ("retained_request_digest", serde_json::json!("c".repeat(64))),
    ] {
        let mut changed = wire.clone();
        changed[field] = value;
        assert!(
            AdmissionCallerDispatchContextV1::from_canonical_bytes(
                &canonical_json_bytes(&changed)?,
                &fixture.operation,
                &fixture.original,
            )
            .is_err(),
            "accepted changed {field}"
        );
    }
    Ok(())
}

#[test]
fn caller_context_insert_failure_rolls_back_operation_and_nonce_history() -> TestResult {
    for table in [
        "admission_operation_caller_contexts",
        "admission_execution_nonce_transitions",
    ] {
        assert_context_insert_rollback(table)?;
    }
    Ok(())
}

fn assert_context_insert_rollback(table: &str) -> TestResult {
    let mut fixture = pending()?;
    let context = context(&fixture)?;
    let before = fixture.operation.clone();
    fixture.fixture.store.connection()?.execute_batch(&format!(
        "CREATE TEMP TRIGGER reject_caller_context BEFORE INSERT ON {table}
         BEGIN SELECT RAISE(ABORT, 'injected context write failure'); END;"
    ))?;
    let error = capture(&mut fixture, &context).expect_err("injected write must fail");
    assert!(
        error.to_string().contains("injected context write failure"),
        "{error}"
    );
    assert_eq!(
        fixture
            .fixture
            .store
            .load_by_operation_id(before.binding().operation_id())?,
        Some(before)
    );
    let transitions: i64 = fixture.fixture.store.connection()?.query_row(
        "SELECT COUNT(*) FROM admission_execution_nonce_transitions",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(transitions, 1);
    assert_eq!(lifecycle::state(&fixture)?, ("authorized".into(), 1, 0));
    let contexts: i64 = fixture.fixture.store.connection()?.query_row(
        "SELECT COUNT(*) FROM admission_operation_caller_contexts",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        contexts, 0,
        "a failed later nonce insertion retained context"
    );
    fixture
        .fixture
        .store
        .connection()?
        .execute_batch("DROP TRIGGER reject_caller_context;")?;
    capture(&mut fixture, &context)?;
    assert_eq!(load(&fixture)?.canonical_bytes(), context.canonical_bytes());
    Ok(())
}

#[test]
fn caller_context_missing_or_changed_physical_rows_fail_closed() -> TestResult {
    for delete in [false, true] {
        let mut fixture = pending()?;
        let context = context(&fixture)?;
        capture(&mut fixture, &context)?;
        {
            let connection = fixture.fixture.store.connection()?;
            let trigger = if delete {
                "admission_operation_caller_contexts_no_delete"
            } else {
                "admission_operation_caller_contexts_immutable"
            };
            let restore: String = connection.query_row(
                "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
                [trigger],
                |row| row.get(0),
            )?;
            if delete {
                connection.execute_batch("DROP TRIGGER admission_operation_caller_contexts_no_delete; DELETE FROM admission_operation_caller_contexts;")?;
            } else {
                let mut wire: serde_json::Value =
                    serde_json::from_slice(context.canonical_bytes())?;
                wire["kernel_context_json"] = serde_json::json!("{\"value\":\"substituted\"}");
                connection
                    .execute_batch("DROP TRIGGER admission_operation_caller_contexts_immutable;")?;
                connection.execute(
                    "UPDATE admission_operation_caller_contexts SET context_json = ?1",
                    [canonical_json_bytes(&wire)?],
                )?;
            }
            // Preserve the exact schema so startup must detect the physical
            // context corruption, not a missing immutability trigger.
            connection.execute_batch(&restore)?;
        }
        let error = fixture
            .fixture
            .store
            .load_by_operation_id(fixture.operation.binding().operation_id())
            .expect_err("physical context corruption must reject the operation read");
        let expected = if delete {
            "lost its physical dispatch context"
        } else {
            "lost its immutable operation attachment"
        };
        assert!(error.to_string().contains(expected), "{error}");
        assert!(load(&fixture).is_err());
        let error = fixture
            .fixture
            .store
            .load_by_replay_key(&fixture.operation.replay_key())
            .expect_err("replay must validate the same physical context");
        assert!(error.to_string().contains(expected), "{error}");
        let error = fixture
            .fixture
            .store
            .list_recoverable(now_ms() + 120_000, 10)
            .expect_err("recovery scan must validate the same physical context");
        assert!(error.to_string().contains(expected), "{error}");
        let error = match lifecycle::reopen(fixture) {
            Ok(_) => return Err("startup accepted corrupt caller context".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains(expected), "{error}");
    }
    Ok(())
}

#[test]
fn caller_context_read_rejects_stale_fences_and_regressed_time() -> TestResult {
    let mut fixture = pending()?;
    let context = context(&fixture)?;
    capture(&mut fixture, &context)?;
    let mut fence = fixture.fixture.fence.clone();
    fence.lease_id = "foreign-owner".into();
    assert!(fixture
        .fixture
        .store
        .load_caller_dispatch_context(fixture.operation.binding().operation_id(), &fence, now_ms())
        .is_err());
    assert!(fixture
        .fixture
        .store
        .load_caller_dispatch_context(
            fixture.operation.binding().operation_id(),
            &fixture.fixture.fence,
            1
        )
        .is_err());
    Ok(())
}

#[test]
fn caller_context_oversized_physical_row_is_rejected_before_decode() -> TestResult {
    let mut fixture = pending()?;
    let context = context(&fixture)?;
    capture(&mut fixture, &context)?;
    {
        let connection = fixture.fixture.store.connection()?;
        connection.execute_batch(
            "DROP TRIGGER admission_operation_caller_contexts_immutable;
             PRAGMA ignore_check_constraints = ON;
             UPDATE admission_operation_caller_contexts SET context_json = zeroblob(1048577);
             PRAGMA ignore_check_constraints = OFF;",
        )?;
    }
    let error = load(&fixture).expect_err("oversized physical context must fail closed");
    assert!(
        error
            .to_string()
            .contains("caller context exceeds its artifact bound"),
        "{error}"
    );
    Ok(())
}

#[test]
fn caller_context_uncommitted_and_orphan_rows_fail_closed() -> TestResult {
    for orphan in [false, true] {
        let fixture = pending()?;
        let context = context(&fixture)?;
        let operation_id = if orphan {
            "nonexistent-operation"
        } else {
            fixture.operation.binding().operation_id().as_str()
        };
        {
            let connection = fixture.fixture.store.connection()?;
            connection.execute_batch("PRAGMA foreign_keys = OFF;")?;
            connection.execute(
                "INSERT INTO admission_operation_caller_contexts (operation_id, context_json)
                 VALUES (?1, ?2)",
                params![operation_id, context.canonical_bytes()],
            )?;
            connection.execute_batch("PRAGMA foreign_keys = ON;")?;
        }
        let expected = if orphan {
            "caller context has no owning admission operation"
        } else {
            "caller dispatch context has no committed operation owner"
        };
        let error = match lifecycle::reopen(fixture) {
            Ok(_) => return Err("startup accepted an unowned caller context".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains(expected), "{error}");
    }
    Ok(())
}

#[test]
fn caller_context_cannot_bind_a_kernel_transport_or_a_pre_dispatch_mutation() -> TestResult {
    let kernel = pending_with_transport("kernel-tool-server:test-server")?;
    assert!(context(&kernel).is_err());
    let fixture = pending()?;
    let context = context(&fixture)?;
    let command = nonce_command(
        &fixture.fixture.store,
        &fixture.fixture.fence,
        &fixture.operation,
        &fixture.key,
        vec![AdmissionAttachment::CallerDispatchContextDigest(
            context.digest().clone(),
        )],
        AdmissionOperationState::CapturePending,
    )?;
    assert!(fixture.operation.apply_command(&command, now_ms()).is_err());
    assert!(fixture
        .fixture
        .store
        .compare_and_swap(&command, now_ms())
        .is_err());
    Ok(())
}

#[test]
fn caller_context_does_not_bypass_live_nonce_validation() -> TestResult {
    let fixture = pending()?;
    let context = context(&fixture)?;
    let command = command(&fixture, &context)?;
    let expired_at = u64::try_from(fixture.reservation.signed_nonce().expires_at())?
        .checked_mul(1_000)
        .ok_or("expiry overflow")?;
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(expired_at / 1_000, []);
    let result = fixture
        .fixture
        .store
        .capture_caller_invocation_and_commit_dispatch(AdmissionCallerDispatchCapture {
            operation: &fixture.operation,
            recovery_lease: command.recovery_lease(),
            request: lifecycle::capture_request(&fixture),
            context: &context,
            active_fence: &fixture.fixture.fence,
            trusted_now_unix_ms: expired_at,
        });
    assert!(
        result
            .as_ref()
            .is_err_and(|error| error.to_string().contains("expired")),
        "{result:?}"
    );
    assert_eq!(
        fixture
            .fixture
            .store
            .load_by_operation_id(fixture.operation.binding().operation_id())?,
        Some(fixture.operation.clone())
    );
    let count: i64 = Connection::open(&fixture.fixture.database)?.query_row(
        "SELECT COUNT(*) FROM admission_operation_caller_contexts",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}

fn mark_v17(fixture: &NonceFixture) -> TestResult {
    let connection = Connection::open(&fixture.fixture.database)?;
    crate::admission_operation_store::tests::runtime_replay::remove_empty_v19_runtime_tables(
        &connection,
    )?;
    connection.execute_batch(
        "DROP TABLE admission_operation_caller_contexts;
         UPDATE chio_store_schema_versions SET version = 17 WHERE store_key = 'admission_operation';",
    )?;
    Ok(())
}

#[test]
fn caller_context_migration_refuses_ambiguous_legacy_caller_reservations() -> TestResult {
    assert_ambiguous_migration_refused(ready()?, false)
}

#[test]
fn caller_context_migration_refuses_unversioned_legacy_callers() -> TestResult {
    assert_ambiguous_migration_refused(ready()?, true)
}

#[test]
fn caller_context_migration_refuses_legacy_compensation_as_proof_of_nonexecution() -> TestResult {
    let fixture = pending()?;
    lifecycle::release(&fixture)?;
    let terminal = fixture
        .fixture
        .store
        .commit_terminal_projection(&lifecycle::projection(&fixture)?)?;
    assert_eq!(
        terminal.state,
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_ambiguous_migration_refused(fixture, false)
}

fn assert_ambiguous_migration_refused(fixture: NonceFixture, unversioned: bool) -> TestResult {
    let database = fixture.fixture.database.clone();
    mark_v17(&fixture)?;
    if unversioned {
        Connection::open(&database)?.execute(
            "DELETE FROM chio_store_schema_versions WHERE store_key = 'admission_operation'",
            [],
        )?;
    }
    drop(fixture.fixture.store);
    drop(fixture.fixture.authority);
    let error = match SqliteAuthorityStore::open_serving(&database, &fixture.fixture.lock_root) {
        Ok(_) => return Err("ambiguous legacy caller was migrated without reconciliation".into()),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("authoritative external-effect reconciliation"),
        "{error}"
    );
    let version: Option<i64> = Connection::open(database)?.query_row(
        "SELECT version FROM chio_store_schema_versions WHERE store_key = 'admission_operation'",
        [],
        |row| row.get(0),
    ).optional()?;
    assert_eq!(
        version,
        if unversioned { None } else { Some(17) },
        "failed migration must not stamp a new version"
    );
    Ok(())
}

#[test]
fn caller_context_migration_preserves_ordinary_nonce_history() -> TestResult {
    let fixture = ready_with_transport("kernel-tool-server:test-server")?;
    let before = fixture.operation.clone();
    mark_v17(&fixture)?;
    let fixture = lifecycle::reopen(fixture)?;
    assert_eq!(fixture.operation, before);
    assert!(fixture
        .fixture
        .store
        .load_caller_dispatch_context(
            fixture.operation.binding().operation_id(),
            &fixture.fixture.fence,
            now_ms()
        )?
        .is_none());
    let version: i64 = Connection::open(&fixture.fixture.database)?.query_row(
        "SELECT version FROM chio_store_schema_versions WHERE store_key = 'admission_operation'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        version,
        i64::from(ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION)
    );
    Ok(())
}
