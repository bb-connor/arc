use super::*;
use chio_kernel::admission_operation::{
    AdmissionExecutionNonceReservationV1, RetainedToolAdmissionRequestV1,
};
use chio_kernel::execution_nonce::{mint_execution_nonce, ExecutionNonceConfig, NonceBinding};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[path = "execution_nonce/lifecycle.rs"]
mod lifecycle;

struct NonceFixture {
    fixture: Fixture,
    operation: AdmissionOperationV1,
    original: RetainedToolAdmissionRequestV1,
    key: Keypair,
    reservation: AdmissionExecutionNonceReservationV1,
}

fn nonce_fixture() -> TestResult<NonceFixture> {
    nonce_fixture_with_budget(false)
}

fn nonce_fixture_with_budget(real_budget: bool) -> TestResult<NonceFixture> {
    nonce_fixture_with_approval_window(real_budget, None)
}

fn nonce_fixture_with_approval_window(
    real_budget: bool,
    approval_seconds: Option<u64>,
) -> TestResult<NonceFixture> {
    let fixture = fixture();
    let (base, original) = retained_request::original(&fixture.fence)?;
    let request = original.request_for_revalidation();
    let namespace = AuthenticatedRequestNamespace::for_local_system(identifier(
        "authority",
        &fixture.fence.store_uuid,
    ))?;
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::ToolDispatch,
        namespace,
        request_id: identifier("request_id", &request.request_id),
        capability_id: identifier("capability_id", &request.capability.id),
        authorization_capability_hash: AdmissionDigest::try_new(
            "capability",
            sha256_hex(&canonical_json_bytes(&request.capability)?),
        )?,
        request_binding: AdmissionRequestBindingV1::new_with_action_parameter_hash(
            base.binding().immutable_request_hash().clone(),
            base.binding().action_parameter_hash().clone(),
            AdmissionParticipantRequirements {
                broker_attempt: true,
                budget_capture: true,
                execution_nonce: true,
                approval: approval_seconds.is_some(),
                ..AdmissionParticipantRequirements::NONE
            },
        )?,
        policy_hash: base.binding().policy_hash().clone(),
        effect_class: SideEffectClass::SideEffecting,
    })?;
    let mut operation = AdmissionOperationV1::prepare(binding, fixture.fence.owner_epoch)?;
    fixture.store.begin_with_retained_tool_request(
        &operation,
        &original,
        &fixture.fence,
        now_ms(),
    )?;
    let key = Keypair::generate();
    for (state, attachment) in [
        (
            AdmissionOperationState::BrokerAttemptRegistered,
            AdmissionAttachment::BrokerAttempt(provider_attempt(&operation, "nonce-attempt")),
        ),
        (
            AdmissionOperationState::BudgetAuthorized,
            AdmissionAttachment::BudgetHoldId(identifier("hold", "nonce-hold")),
        ),
    ] {
        let command = nonce_command(
            &fixture.store,
            &fixture.fence,
            &operation,
            &key,
            vec![attachment],
            state,
        )?;
        operation = if real_budget && state == AdmissionOperationState::BudgetAuthorized {
            fixture
                .store
                .authorize_budget_and_commit_admission(
                    &operation,
                    command.recovery_lease(),
                    lifecycle::budget_request(&fixture, &operation),
                    None,
                    None,
                    &fixture.fence,
                    now_ms(),
                )?
                .1
        } else {
            fixture
                .store
                .compare_and_swap(&command, now_ms())?
                .into_operation()
        };
    }
    if let Some(seconds) = approval_seconds {
        operation = lifecycle::reserve_approvals(&fixture, &operation, &original, &key, seconds)?;
    }
    let signed = mint_execution_nonce(
        &key,
        NonceBinding {
            subject_id: request.capability.subject.to_hex(),
            request_id: request.request_id.clone(),
            capability_id: request.capability.id.clone(),
            tool_server: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            parameter_hash: operation.binding().action_parameter_hash().as_str().into(),
        },
        &ExecutionNonceConfig::default(),
        i64::try_from(now_ms() / 1000)?,
    )?;
    let reservation = AdmissionExecutionNonceReservationV1::verify(
        &operation,
        &original,
        &signed,
        &key.public_key(),
        now_ms(),
    )?;
    Ok(NonceFixture {
        fixture,
        operation,
        original,
        key,
        reservation,
    })
}

fn nonce_command(
    store: &SqliteAdmissionOperationStore,
    fence: &StoreMutationFence,
    operation: &AdmissionOperationV1,
    key: &Keypair,
    attachments: Vec<AdmissionAttachment>,
    state: AdmissionOperationState,
) -> TestResult<AdmissionOperationCommand> {
    let now = now_ms();
    let lease = store.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        &identifier("claimant", &format!("kernel:{}", key.public_key().to_hex())),
        now,
        now + 60_000,
        fence,
    )?;
    Ok(AdmissionOperationCommand::new(
        operation.binding().operation_id().clone(),
        operation.version(),
        lease,
        attachments,
        Some(state),
        None,
        None,
    )?)
}

fn reserve_command(fixture: &NonceFixture) -> TestResult<AdmissionOperationCommand> {
    nonce_command(
        &fixture.fixture.store,
        &fixture.fixture.fence,
        &fixture.operation,
        &fixture.key,
        vec![AdmissionAttachment::ExecutionNonceId(
            fixture.reservation.nonce_id().clone(),
        )],
        AdmissionOperationState::ReadyToDispatch,
    )
}

#[test]
fn durable_nonce_reservation_is_atomic_fenced_and_replays_after_restart() -> TestResult {
    let mut fixture = nonce_fixture()?;
    let command = reserve_command(&fixture)?;
    fixture.operation = fixture
        .fixture
        .store
        .reserve_execution_nonce_and_commit_admission(&command, &fixture.reservation, now_ms())?
        .into_operation();
    assert_eq!(
        fixture.operation.state(),
        AdmissionOperationState::ReadyToDispatch
    );
    let replay = reserve_command(&fixture)?;
    assert!(matches!(
        fixture
            .fixture
            .store
            .reserve_execution_nonce_and_commit_admission(
                &replay,
                &fixture.reservation,
                now_ms(),
            )?,
        AdmissionCommandResult::Idempotent(_)
    ));
    let operation_id = fixture.operation.binding().operation_id().clone();
    let expected = fixture.reservation.canonical_bytes().to_vec();
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        fence,
    } = fixture.fixture;
    drop(store);
    drop(authority);
    let reopened = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let store = reopened.admission_operation_store();
    assert!(matches!(
        store.load_execution_nonce_reservation(&operation_id, &fence, now_ms()),
        Err(AdmissionOperationStoreError::Fenced)
    ));
    let retained = store
        .load_execution_nonce_reservation(&operation_id, &reopened.mutation_fence(), now_ms())?
        .ok_or("lost reservation")?;
    assert_eq!(retained.canonical_bytes(), expected);
    assert_eq!(
        format!("{retained:?}"),
        "AdmissionExecutionNonceReservationV1 { .. }"
    );
    let count: i64 = Connection::open(database)?.query_row(
        "SELECT COUNT(*) FROM admission_execution_nonce_reservations",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 1);
    Ok(())
}

#[test]
fn durable_nonce_reservation_rolls_back_on_operation_or_record_write_failure() -> TestResult {
    for (table, mutation) in [
        ("admission_operations", "UPDATE"),
        ("admission_operation_commits", "INSERT"),
        ("admission_execution_nonce_reservations", "INSERT"),
    ] {
        let fixture = nonce_fixture()?;
        let command = reserve_command(&fixture)?;
        let connection = Connection::open(&fixture.fixture.database)?;
        let before: i64 = connection.query_row(
            "SELECT COUNT(*) FROM admission_operation_commits",
            [],
            |row| row.get(0),
        )?;
        fixture.fixture.store.connection()?.execute_batch(&format!("CREATE TRIGGER fail_nonce BEFORE {mutation} ON {table} BEGIN SELECT RAISE(ABORT, 'injected nonce failure'); END;"))?;
        let error = fixture
            .fixture
            .store
            .reserve_execution_nonce_and_commit_admission(&command, &fixture.reservation, now_ms())
            .expect_err("injected cutpoint succeeded");
        assert!(
            error.to_string().contains("injected nonce failure"),
            "{error}"
        );
        assert_eq!(
            fixture
                .fixture
                .store
                .load_by_operation_id(fixture.operation.binding().operation_id())?,
            Some(fixture.operation.clone())
        );
        let after: i64 = connection.query_row(
            "SELECT COUNT(*) FROM admission_operation_commits",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(before, after);
        assert!(fixture
            .fixture
            .store
            .load_execution_nonce_reservation(
                fixture.operation.binding().operation_id(),
                &fixture.fixture.fence,
                now_ms()
            )?
            .is_none());
    }
    Ok(())
}

#[test]
fn durable_nonce_generic_cas_cannot_invent_or_advance_a_reservation() -> TestResult {
    let mut fixture = nonce_fixture()?;
    let command = reserve_command(&fixture)?;
    let error = fixture
        .fixture
        .store
        .compare_and_swap(&command, now_ms())
        .expect_err("raw nonce attachment accepted");
    assert!(error.to_string().contains("atomic participant"), "{error}");
    fixture.operation = fixture
        .fixture
        .store
        .reserve_execution_nonce_and_commit_admission(&command, &fixture.reservation, now_ms())?
        .into_operation();
    let command = nonce_command(
        &fixture.fixture.store,
        &fixture.fixture.fence,
        &fixture.operation,
        &fixture.key,
        vec![],
        AdmissionOperationState::CapturePending,
    )?;
    let error = fixture
        .fixture
        .store
        .compare_and_swap(&command, now_ms())
        .expect_err("capture advanced without committing its nonce");
    assert!(error.to_string().contains("atomic participant"), "{error}");
    Ok(())
}

#[test]
fn durable_nonce_reservation_rechecks_issuer_and_expiry_before_mutation() -> TestResult {
    let fixture = nonce_fixture()?;
    let command = reserve_command(&fixture)?;
    let wrong_key = Keypair::generate();
    let mut wire: serde_json::Value =
        serde_json::from_slice(fixture.reservation.canonical_bytes())?;
    let mut signed: chio_kernel::execution_nonce::SignedExecutionNonce =
        serde_json::from_value(wire["signed_nonce"].clone())?;
    signed.signature = wrong_key.sign(&canonical_json_bytes(&signed.nonce)?);
    let wrong_issuer = AdmissionExecutionNonceReservationV1::verify(
        &fixture.operation,
        &fixture.original,
        &signed,
        &wrong_key.public_key(),
        now_ms(),
    )?;
    let error = fixture
        .fixture
        .store
        .reserve_execution_nonce_and_commit_admission(&command, &wrong_issuer, now_ms())
        .expect_err("different trusted key replaced the coordinator");
    assert!(
        error.to_string().contains("qualified coordinator"),
        "{error}"
    );
    wire["issuer"] = serde_json::to_value(wrong_key.public_key())?;
    assert!(AdmissionExecutionNonceReservationV1::from_canonical_bytes(
        &canonical_json_bytes(&wire)?,
        &fixture.operation,
        &fixture.original,
        &fixture.key.public_key(),
        now_ms()
    )
    .is_err());
    let expires = wire["signed_nonce"]["nonce"]["expires_at"]
        .as_u64()
        .ok_or("missing expiry")?
        * 1000;
    let error = fixture
        .fixture
        .store
        .reserve_execution_nonce_and_commit_admission(&command, &fixture.reservation, expires)
        .expect_err("expired nonce reached durable reservation");
    assert!(
        error.to_string().contains("execution nonce expired"),
        "{error}"
    );
    assert!(fixture
        .fixture
        .store
        .load_execution_nonce_reservation(
            fixture.operation.binding().operation_id(),
            &fixture.fixture.fence,
            now_ms()
        )?
        .is_none());
    Ok(())
}

#[test]
fn durable_nonce_tampering_removal_and_oversized_storage_fail_reads_and_restart() -> TestResult {
    for (mutation, expected) in [
        ("DROP TRIGGER admission_execution_nonce_reservations_no_delete;
          DELETE FROM admission_execution_nonce_reservations;", "no durable reservation"),
        ("DROP TRIGGER admission_execution_nonce_reservations_immutable;
          UPDATE admission_execution_nonce_reservations SET reserved_at_unix_ms = reserved_at_unix_ms + 1;", "exact admission commit"),
        ("DROP TRIGGER admission_execution_nonce_reservations_immutable;
          PRAGMA ignore_check_constraints = ON;
          UPDATE admission_execution_nonce_reservations SET reservation_json = zeroblob(16385);
          PRAGMA ignore_check_constraints = OFF;", "storage bound"),
    ] {
        let fixture = nonce_fixture()?;
        let command = reserve_command(&fixture)?;
        fixture.fixture.store.reserve_execution_nonce_and_commit_admission(
            &command, &fixture.reservation, now_ms())?;
        fixture.fixture.store.connection()?.execute_batch(mutation)?;
        let error = fixture.fixture.store.load_by_operation_id(fixture.operation.binding().operation_id())
            .expect_err("corrupted nonce reservation was accepted");
        assert!(error.to_string().contains(expected), "{error}");
        let Fixture { _temp, database, lock_root, authority, store, .. } = fixture.fixture;
        drop(store);
        drop(authority);
        assert!(SqliteAuthorityStore::open_serving(&database, &lock_root).is_err());
    }
    Ok(())
}

#[test]
fn durable_nonce_identity_cannot_be_updated_or_deleted() -> TestResult {
    let fixture = nonce_fixture()?;
    let command = reserve_command(&fixture)?;
    fixture
        .fixture
        .store
        .reserve_execution_nonce_and_commit_admission(&command, &fixture.reservation, now_ms())?;
    let connection = fixture.fixture.store.connection()?;
    for statement in [
        "DELETE FROM admission_execution_nonce_reservations",
        "UPDATE admission_execution_nonce_reservations SET nonce_id = 'replacement'",
    ] {
        assert!(connection.execute(statement, []).is_err());
    }
    Ok(())
}

#[test]
fn durable_nonce_expired_reservation_remains_available_only_as_history() -> TestResult {
    let mut fixture = nonce_fixture()?;
    let command = reserve_command(&fixture)?;
    fixture.operation = fixture
        .fixture
        .store
        .reserve_execution_nonce_and_commit_admission(&command, &fixture.reservation, now_ms())?
        .into_operation();
    let replay = reserve_command(&fixture)?;
    let wire: serde_json::Value = serde_json::from_slice(fixture.reservation.canonical_bytes())?;
    let expires = wire["signed_nonce"]["nonce"]["expires_at"]
        .as_u64()
        .ok_or("missing expiry")?
        * 1000;
    let historical = fixture
        .fixture
        .store
        .load_execution_nonce_reservation(
            fixture.operation.binding().operation_id(),
            &fixture.fixture.fence,
            expires,
        )?
        .ok_or("expired history disappeared")?;
    assert_eq!(
        historical.canonical_bytes(),
        fixture.reservation.canonical_bytes()
    );
    assert!(AdmissionExecutionNonceReservationV1::from_canonical_bytes(
        historical.canonical_bytes(),
        &fixture.operation,
        &fixture.original,
        &fixture.key.public_key(),
        expires
    )
    .is_err());
    let error = fixture
        .fixture
        .store
        .reserve_execution_nonce_and_commit_admission(&replay, &historical, expires)
        .expect_err("expired history authorized a reservation replay");
    assert!(
        error.to_string().contains("execution nonce expired"),
        "{error}"
    );
    Ok(())
}

#[test]
fn durable_nonce_v11_migration_preserves_original_commits_without_inventing_reservations(
) -> TestResult {
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        fence,
    } = fixture();
    let (operation, original) = retained_request::original(&fence)?;
    store.begin_with_retained_tool_request(&operation, &original, &fence, now_ms())?;
    drop(store);
    drop(authority);
    let connection = Connection::open(&database)?;
    let before: Vec<u8> = connection.query_row(
        "SELECT operation_json FROM admission_operations",
        [],
        |row| row.get(0),
    )?;
    connection.execute_batch("DROP TABLE admission_execution_nonce_transitions;
        DROP TABLE admission_execution_nonce_reservations;
        UPDATE chio_store_schema_versions SET version = 11 WHERE store_key = 'admission_operation';")?;
    drop(connection);
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let reopened = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let store = reopened.admission_operation_store();
    let (_, retained) = store
        .load_retained_tool_request(
            operation.binding().operation_id(),
            &reopened.mutation_fence(),
            now_ms(),
        )?
        .ok_or("original request lost in migration")?;
    assert_eq!(retained.canonical_bytes(), original.canonical_bytes());
    let connection = Connection::open(&database)?;
    let after: Vec<u8> = connection.query_row(
        "SELECT operation_json FROM admission_operations",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(before, after);
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM admission_execution_nonce_reservations",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn durable_nonce_decoder_rejects_unbound_noncanonical_and_future_artifacts() -> TestResult {
    let fixture = nonce_fixture()?;
    let mut noncanonical = fixture.reservation.canonical_bytes().to_vec();
    noncanonical.push(b' ');
    let error = AdmissionExecutionNonceReservationV1::from_canonical_bytes(
        &noncanonical,
        &fixture.operation,
        &fixture.original,
        &fixture.key.public_key(),
        now_ms(),
    )
    .expect_err("noncanonical nonce record accepted");
    assert!(error.to_string().contains("canonical JSON"), "{error}");
    let mut wire: serde_json::Value =
        serde_json::from_slice(fixture.reservation.canonical_bytes())?;
    wire["signed_nonce"]["nonce"]["issued_at"] = serde_json::json!(now_ms() / 1000 + 10);
    let error = AdmissionExecutionNonceReservationV1::from_canonical_bytes(
        &canonical_json_bytes(&wire)?,
        &fixture.operation,
        &fixture.original,
        &fixture.key.public_key(),
        now_ms(),
    )
    .expect_err("future issuance interval accepted");
    assert!(error.to_string().contains("issuance interval"), "{error}");
    wire["operation_id"] = serde_json::json!("a".repeat(64));
    let error = AdmissionExecutionNonceReservationV1::from_canonical_bytes(
        &canonical_json_bytes(&wire)?,
        &fixture.operation,
        &fixture.original,
        &fixture.key.public_key(),
        now_ms(),
    )
    .expect_err("wrong operation accepted");
    assert!(error.to_string().contains("binding is invalid"), "{error}");
    Ok(())
}

#[test]
fn durable_nonce_contenders_in_distinct_namespaces_share_one_replay_identity() -> TestResult {
    let fixture = nonce_fixture()?;
    let first_command = reserve_command(&fixture)?;
    let binding = fixture.operation.binding().to_persisted();
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: binding.kind,
        namespace: AuthenticatedRequestNamespace::for_local_system(identifier(
            "authority",
            "second-coordinator-namespace",
        ))?,
        request_id: binding.request_id,
        capability_id: binding.capability_id,
        authorization_capability_hash: binding.authorization_capability_hash,
        request_binding: binding.request_binding,
        policy_hash: binding.policy_hash,
        effect_class: binding.effect_class,
    })?;
    let mut second = AdmissionOperationV1::prepare(binding, fixture.fixture.fence.owner_epoch)?;
    fixture.fixture.store.begin_with_retained_tool_request(
        &second,
        &fixture.original,
        &fixture.fixture.fence,
        now_ms(),
    )?;
    for (state, attachment) in [
        (
            AdmissionOperationState::BrokerAttemptRegistered,
            AdmissionAttachment::BrokerAttempt(provider_attempt(&second, "second-attempt")),
        ),
        (
            AdmissionOperationState::BudgetAuthorized,
            AdmissionAttachment::BudgetHoldId(identifier("hold", "second-hold")),
        ),
    ] {
        let command = nonce_command(
            &fixture.fixture.store,
            &fixture.fixture.fence,
            &second,
            &fixture.key,
            vec![attachment],
            state,
        )?;
        second = fixture
            .fixture
            .store
            .compare_and_swap(&command, now_ms())?
            .into_operation();
    }
    let wire: serde_json::Value = serde_json::from_slice(fixture.reservation.canonical_bytes())?;
    let signed = serde_json::from_value(wire["signed_nonce"].clone())?;
    let reservation = AdmissionExecutionNonceReservationV1::verify(
        &second,
        &fixture.original,
        &signed,
        &fixture.key.public_key(),
        now_ms(),
    )?;
    let second_command = nonce_command(
        &fixture.fixture.store,
        &fixture.fixture.fence,
        &second,
        &fixture.key,
        vec![AdmissionAttachment::ExecutionNonceId(
            reservation.nonce_id().clone(),
        )],
        AdmissionOperationState::ReadyToDispatch,
    )?;
    let barrier = std::sync::Barrier::new(2);
    let results = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            barrier.wait();
            fixture
                .fixture
                .store
                .reserve_execution_nonce_and_commit_admission(
                    &first_command,
                    &fixture.reservation,
                    now_ms(),
                )
        });
        let second = scope.spawn(|| {
            barrier.wait();
            fixture
                .fixture
                .store
                .reserve_execution_nonce_and_commit_admission(
                    &second_command,
                    &reservation,
                    now_ms(),
                )
        });
        Ok::<_, Box<dyn Error>>([
            first.join().map_err(|_| "first nonce worker panicked")?,
            second.join().map_err(|_| "second nonce worker panicked")?,
        ])
    })?;
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let error = results
        .into_iter()
        .find_map(Result::err)
        .ok_or("no rejected contender")?;
    assert!(
        error.to_string().contains("UNIQUE constraint failed"),
        "{error}"
    );
    let mut states = vec![
        fixture
            .fixture
            .store
            .load_by_operation_id(fixture.operation.binding().operation_id())?
            .ok_or("first operation lost")?
            .state(),
        fixture
            .fixture
            .store
            .load_by_operation_id(second.binding().operation_id())?
            .ok_or("second operation lost")?
            .state(),
    ];
    assert_eq!(
        states
            .iter()
            .filter(|state| **state == AdmissionOperationState::ReadyToDispatch)
            .count(),
        1
    );
    states.retain(|state| *state != AdmissionOperationState::ReadyToDispatch);
    assert_eq!(states, [AdmissionOperationState::BudgetAuthorized]);
    Ok(())
}
