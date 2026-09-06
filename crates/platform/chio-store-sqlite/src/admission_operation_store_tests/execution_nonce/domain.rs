use super::*;
use crate::SqliteExecutionNonceStore;
use chio_kernel::execution_nonce::{verify_execution_nonce, SignedExecutionNonce};
use chio_kernel::ExecutionNonceStore;

pub(super) fn sign_for(
    operation: &AdmissionOperationV1,
    nonce: &mut SignedExecutionNonce,
    key: &Keypair,
) -> TestResult {
    nonce.signature = key.sign(&canonical_json_bytes(&serde_json::json!({
        "schema": "chio.admission-execution-nonce-signature.v1",
        "operation_id": operation.binding().operation_id(),
        "nonce": nonce.nonce,
    }))?);
    Ok(())
}

fn signed(fixture: &NonceFixture) -> TestResult<SignedExecutionNonce> {
    let wire: serde_json::Value = serde_json::from_slice(fixture.reservation.canonical_bytes())?;
    Ok(serde_json::from_value(wire["signed_nonce"].clone())?)
}

fn legacy_packet(fixture: &NonceFixture) -> TestResult<SignedExecutionNonce> {
    Ok(mint_execution_nonce(
        &fixture.key,
        signed(fixture)?.nonce.bound_to,
        &ExecutionNonceConfig::default(),
        i64::try_from(now_ms() / 1_000)?,
    )?)
}

pub(super) fn legacy_ready(real_budget: bool) -> TestResult<NonceFixture> {
    let mut fixture = nonce_fixture_with_budget(real_budget)?;
    let nonce = legacy_packet(&fixture)?;
    fixture.reservation = AdmissionExecutionNonceReservationV1::verify(
        &fixture.operation,
        &fixture.original,
        &nonce,
        &fixture.key.public_key(),
        now_ms(),
    )?;
    let command = reserve_command(&fixture)?;
    let at = now_ms();
    let updated = fixture
        .operation
        .apply_command(&command, at)?
        .into_operation();
    let ready = canonical_json_bytes(&updated.to_persisted())?;
    // Reconstruct the v12/v13 writer's canonical commit, including the shared
    // authority chain and anchor. The current fresh-reservation port must refuse
    // this legacy signature profile; migration fixtures exercise historical data.
    let digest = sha256_hex(&canonical_json_bytes(&serde_json::json!({
        "schema": "chio.admission-execution-nonce-commit.v1",
        "reservation_digest": sha256_hex(fixture.reservation.canonical_bytes()),
        "ready_operation_digest": sha256_hex(&ready),
        "reserved_at_unix_ms": at,
    }))?);
    {
        let store = &fixture.fixture.store;
        let mut connection = store.connection()?;
        let transaction = store.begin_write(&mut connection, Some(&fixture.fixture.fence))?;
        crate::admission_operation_store::participant::advance_participant_bound_operation_tx(
            &transaction,
            &store.serving_owner,
            &fixture.operation,
            command.recovery_lease(),
            &updated,
            &digest,
            at,
        )?;
        transaction.execute(
            "INSERT INTO admission_execution_nonce_reservations (
                operation_id, nonce_id, issuer, reservation_json, ready_operation_json, reserved_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![updated.binding().operation_id().as_str(), fixture.reservation.nonce_id().as_str(),
                fixture.key.public_key().to_hex(), fixture.reservation.canonical_bytes(), ready,
                i64::try_from(at)?],
        )?;
        store.commit_write(transaction)?;
        store.sync_after_write(&connection)?;
    }
    fixture.operation = updated;
    Ok(fixture)
}

#[test]
fn durable_nonce_domain_rejects_legacy_consumption_after_admission() -> TestResult {
    let fixture = nonce_fixture()?;
    fixture
        .fixture
        .store
        .reserve_execution_nonce_and_commit_admission(
            &reserve_command(&fixture)?,
            &fixture.reservation,
            now_ms(),
        )?;
    let nonce = signed(&fixture)?;
    let legacy = SqliteExecutionNonceStore::open(
        fixture.fixture._temp.path().join("independent-legacy.db"),
    )?;
    assert!(
        verify_execution_nonce(
            &nonce,
            &fixture.key.public_key(),
            &nonce.nonce.bound_to,
            i64::try_from(now_ms() / 1_000)?,
            &legacy,
        )
        .is_err(),
        "the same signed nonce authorized both replay stores"
    );
    assert!(!legacy.is_consumed(nonce.nonce_id())?);
    Ok(())
}

#[test]
fn durable_nonce_domain_rejects_admission_after_legacy_consumption() -> TestResult {
    let mut fixture = nonce_fixture()?;
    let nonce = legacy_packet(&fixture)?;
    let legacy = SqliteExecutionNonceStore::open(
        fixture.fixture._temp.path().join("independent-legacy.db"),
    )?;
    verify_execution_nonce(
        &nonce,
        &fixture.key.public_key(),
        &nonce.nonce.bound_to,
        i64::try_from(now_ms() / 1_000)?,
        &legacy,
    )?;
    fixture.reservation = AdmissionExecutionNonceReservationV1::verify(
        &fixture.operation,
        &fixture.original,
        &nonce,
        &fixture.key.public_key(),
        now_ms(),
    )?;
    assert!(
        fixture
            .fixture
            .store
            .reserve_execution_nonce_and_commit_admission(
                &reserve_command(&fixture)?,
                &fixture.reservation,
                now_ms(),
            )
            .is_err(),
        "legacy-consumed nonce entered a fresh durable admission"
    );
    assert!(legacy.is_consumed(nonce.nonce_id())?);
    assert_eq!(
        fixture
            .fixture
            .store
            .load_by_operation_id(fixture.operation.binding().operation_id(),)?,
        Some(fixture.operation.clone())
    );
    Ok(())
}

#[test]
fn durable_nonce_domain_requires_exact_operation_signature_context() -> TestResult {
    let fixture = nonce_fixture()?;
    let nonce = signed(&fixture)?;
    let context = canonical_json_bytes(&serde_json::json!({
        "schema": "chio.admission-execution-nonce-signature.v1",
        "operation_id": fixture.operation.binding().operation_id(),
        "nonce": nonce.nonce,
    }))?;
    assert!(fixture.key.public_key().verify(&context, &nonce.signature));
    assert!(!fixture
        .key
        .public_key()
        .verify(&canonical_json_bytes(&nonce.nonce)?, &nonce.signature));
    for change_namespace in [false, true] {
        let binding = fixture.operation.binding().to_persisted();
        let alternate = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
            kind: binding.kind,
            namespace: AuthenticatedRequestNamespace::for_local_system(identifier(
                "authority",
                if change_namespace {
                    "alternate-authority"
                } else {
                    &fixture.fixture.fence.store_uuid
                },
            ))?,
            request_id: binding.request_id,
            capability_id: binding.capability_id,
            authorization_capability_hash: binding.authorization_capability_hash,
            request_binding: binding.request_binding,
            policy_hash: if change_namespace {
                binding.policy_hash
            } else {
                digest("policy", 'f')
            },
            effect_class: binding.effect_class,
        })?;
        let alternate =
            AdmissionOperationV1::prepare(alternate, fixture.fixture.fence.owner_epoch)?;
        let error = AdmissionExecutionNonceReservationV1::verify(
            &alternate,
            &fixture.original,
            &nonce,
            &fixture.key.public_key(),
            now_ms(),
        )
        .expect_err("nonce changed its signed operation");
        assert!(
            error
                .to_string()
                .contains("operation-bound execution nonce signature"),
            "{error}"
        );
    }
    Ok(())
}

#[test]
fn durable_nonce_domain_rejects_schema_relabeling() -> TestResult {
    let fixture = nonce_fixture()?;
    let legacy = SqliteExecutionNonceStore::open_in_memory()?;
    let mut downgraded = signed(&fixture)?;
    downgraded.nonce.schema = "chio.execution_nonce.v1".into();
    assert!(verify_execution_nonce(
        &downgraded,
        &fixture.key.public_key(),
        &downgraded.nonce.bound_to,
        i64::try_from(now_ms() / 1_000)?,
        &legacy,
    )
    .is_err());
    assert!(!legacy.is_consumed(downgraded.nonce_id())?);
    let mut upgraded = legacy_packet(&fixture)?;
    upgraded.nonce.schema = "chio.execution_nonce.v2".into();
    assert!(AdmissionExecutionNonceReservationV1::verify(
        &fixture.operation,
        &fixture.original,
        &upgraded,
        &fixture.key.public_key(),
        now_ms(),
    )
    .is_err());
    Ok(())
}

#[test]
fn durable_nonce_domain_checks_every_bound_field() -> TestResult {
    let fixture = nonce_fixture()?;
    for field in [
        "subject_id",
        "request_id",
        "capability_id",
        "tool_server",
        "tool_name",
        "parameter_hash",
    ] {
        let mut wire = serde_json::to_value(signed(&fixture)?)?;
        wire["nonce"]["bound_to"][field] = serde_json::json!("f".repeat(64));
        let mut nonce = serde_json::from_value(wire)?;
        sign_for(&fixture.operation, &mut nonce, &fixture.key)?;
        let error = AdmissionExecutionNonceReservationV1::verify(
            &fixture.operation,
            &fixture.original,
            &nonce,
            &fixture.key.public_key(),
            now_ms(),
        )
        .expect_err("nonce changed a signed request field");
        assert!(error.to_string().contains(field), "{field}: {error}");
    }
    Ok(())
}

#[test]
fn durable_nonce_domain_checks_mint_bounds_and_canonical_decode() -> TestResult {
    let fixture = nonce_fixture()?;
    for (ttl, at) in [
        (0, now_ms()),
        (u64::MAX, now_ms()),
        (30, 9_007_199_254_740_991),
    ] {
        let config = ExecutionNonceConfig {
            nonce_ttl_secs: ttl,
            ..ExecutionNonceConfig::default()
        };
        assert!(AdmissionExecutionNonceReservationV1::mint_for_operation(
            &fixture.operation,
            &fixture.original,
            &fixture.key,
            &config,
            at,
        )
        .is_err());
    }
    let decoded = AdmissionExecutionNonceReservationV1::from_canonical_bytes(
        fixture.reservation.canonical_bytes(),
        &fixture.operation,
        &fixture.original,
        &fixture.key.public_key(),
        now_ms(),
    )?;
    decoded.require_operation_bound_profile()?;
    assert_eq!(decoded.signed_nonce(), fixture.reservation.signed_nonce());
    let legacy = legacy_packet(&fixture)?;
    let historical = AdmissionExecutionNonceReservationV1::verify(
        &fixture.operation,
        &fixture.original,
        &legacy,
        &fixture.key.public_key(),
        now_ms(),
    )?;
    assert!(historical.require_operation_bound_profile().is_err());
    Ok(())
}

#[test]
fn durable_nonce_domain_v13_ready_history_cannot_regain_authority() -> TestResult {
    let mut fixture = legacy_ready(true)?;
    let retained = fixture.reservation.canonical_bytes().to_vec();
    fixture.fixture.store.connection()?.execute(
        "UPDATE chio_store_schema_versions SET version = 13 WHERE store_key = 'admission_operation'", [],
    )?;
    fixture = lifecycle::reopen(fixture)?;
    let command = nonce_command(
        &fixture.fixture.store,
        &fixture.fixture.fence,
        &fixture.operation,
        &fixture.key,
        Vec::new(),
        AdmissionOperationState::CapturePending,
    )?;
    let error = fixture
        .fixture
        .store
        .begin_execution_nonce_capture(&command, now_ms())
        .expect_err("legacy history became fresh capture authority");
    assert!(
        error.to_string().contains("operation-bound profile"),
        "{error}"
    );
    let retry = reserve_command(&fixture)?;
    assert!(fixture
        .fixture
        .store
        .reserve_execution_nonce_and_commit_admission(&retry, &fixture.reservation, now_ms(),)
        .is_err());
    assert_eq!(lifecycle::state(&fixture)?, ("authorized".into(), 0, 0));
    lifecycle::release(&fixture)?;
    fixture
        .fixture
        .store
        .commit_terminal_projection(&lifecycle::projection(&fixture)?)?;
    fixture = lifecycle::reopen(fixture)?;
    assert_eq!(
        fixture.operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(lifecycle::state(&fixture)?, ("reversed".into(), 1, 0));
    assert_eq!(
        fixture
            .fixture
            .store
            .load_execution_nonce_reservation(
                fixture.operation.binding().operation_id(),
                &fixture.fixture.fence,
                now_ms(),
            )?
            .ok_or("lost legacy evidence")?
            .canonical_bytes(),
        retained
    );
    Ok(())
}

#[test]
fn durable_nonce_domain_v13_pending_capture_rolls_back_and_can_cancel() -> TestResult {
    let mut fixture = legacy_ready(true)?;
    let command = nonce_command(
        &fixture.fixture.store,
        &fixture.fixture.fence,
        &fixture.operation,
        &fixture.key,
        Vec::new(),
        AdmissionOperationState::CapturePending,
    )?;
    let at = now_ms();
    let pending = fixture
        .operation
        .apply_command(&command, at)?
        .into_operation();
    let pending_bytes = canonical_json_bytes(&pending.to_persisted())?;
    let digest = sha256_hex(&canonical_json_bytes(&serde_json::json!({
        "schema": "chio.admission-execution-nonce-capture-preparation.v1",
        "reservation_digest": sha256_hex(fixture.reservation.canonical_bytes()),
        "operation_digest": sha256_hex(&pending_bytes),
        "recorded_at_unix_ms": at,
    }))?);
    // Construct the exact previous writer's prepared phase, not new authority.
    {
        let store = &fixture.fixture.store;
        let mut connection = store.connection()?;
        let transaction = store.begin_write(&mut connection, Some(&fixture.fixture.fence))?;
        crate::admission_operation_store::participant::advance_participant_bound_operation_tx(
            &transaction,
            &store.serving_owner,
            &fixture.operation,
            command.recovery_lease(),
            &pending,
            &digest,
            at,
        )?;
        transaction.execute(
            "INSERT INTO admission_execution_nonce_transitions (
                operation_id, kind, operation_json, recorded_at_unix_ms, participant_digest
             ) VALUES (?1, 'capture_pending', ?2, ?3, ?4)",
            params![
                pending.binding().operation_id().as_str(),
                pending_bytes,
                i64::try_from(at)?,
                digest
            ],
        )?;
        store.commit_write(transaction)?;
        store.sync_after_write(&connection)?;
    }
    fixture.operation = pending;
    fixture.fixture.store.connection()?.execute(
        "UPDATE chio_store_schema_versions SET version = 13 WHERE store_key = 'admission_operation'", [],
    )?;
    fixture = lifecycle::reopen(fixture)?;
    let command = nonce_command(
        &fixture.fixture.store,
        &fixture.fixture.fence,
        &fixture.operation,
        &fixture.key,
        Vec::new(),
        AdmissionOperationState::CapturePending,
    )?;
    let error = fixture
        .fixture
        .store
        .capture_invocation_and_commit_dispatch(
            &fixture.operation,
            command.recovery_lease(),
            lifecycle::capture_request(&fixture),
            &fixture.fixture.fence,
            now_ms(),
        )
        .expect_err("legacy prepared nonce captured a quota");
    assert!(
        error.to_string().contains("operation-bound profile"),
        "{error}"
    );
    assert_eq!(lifecycle::state(&fixture)?, ("authorized".into(), 1, 0));
    lifecycle::release(&fixture)?;
    fixture
        .fixture
        .store
        .commit_terminal_projection(&lifecycle::projection(&fixture)?)?;
    fixture = lifecycle::reopen(fixture)?;
    assert_eq!(
        fixture.operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(lifecycle::state(&fixture)?, ("reversed".into(), 2, 0));
    Ok(())
}
