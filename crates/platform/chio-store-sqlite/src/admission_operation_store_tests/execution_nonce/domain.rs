use super::*;
use crate::SqliteExecutionNonceStore;
use chio_kernel::execution_nonce::{verify_execution_nonce, SignedExecutionNonce};
use chio_kernel::ExecutionNonceStore;

const OPERATION_NONCE_SCHEMA: &str = "chio.operation_execution_nonce.v1";

fn operation_nonce_body(
    operation: &AdmissionOperationV1,
    nonce: &SignedExecutionNonce,
) -> TestResult<chio_core::CanonicalBytes> {
    Ok(chio_core::CanonicalBytes::from_serializable(&serde_json::json!({
        "operation_id": operation.binding().operation_id(),
        "nonce": nonce.nonce,
    }))?)
}

pub(super) fn sign_for(
    operation: &AdmissionOperationV1,
    nonce: &mut SignedExecutionNonce,
    key: &Keypair,
) -> TestResult {
    let body = operation_nonce_body(operation, nonce)?;
    nonce.signature = key.sign_wrapped(OPERATION_NONCE_SCHEMA, &body)?;
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
    let context = operation_nonce_body(&fixture.operation, &nonce)?;
    chio_core::crypto::verify_wrapped_bytes(
        &fixture.key.public_key(),
        OPERATION_NONCE_SCHEMA,
        &context,
        &nonce.signature,
    )?;
    assert!(matches!(
        chio_core::crypto::verify_wrapped(
            &fixture.key.public_key(),
            chio_core::message::CHIO_EXECUTION_NONCE_SCHEMA,
            &nonce.nonce,
            &nonce.signature,
        ),
        Err(chio_core::Error::SignatureRejected)
    ));
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
    let decoded = AdmissionExecutionNonceReservationV1::from_canonical_bytes(
        fixture.reservation.canonical_bytes(),
        &fixture.operation,
        &fixture.original,
        &fixture.key.public_key(),
        now_ms(),
    )?;
    decoded.require_operation_bound_profile()?;
    assert_eq!(decoded.signed_nonce(), fixture.reservation.signed_nonce());

    for schema in [
        "chio.execution_nonce.v2",
        "chio.execution_nonce.v3",
        "chio.operation_execution_nonce.v2",
        "chio.operation_execution_nonce.v3",
    ] {
        let mut nonce = signed(&fixture)?;
        nonce.nonce.schema = schema.into();
        sign_for(&fixture.operation, &mut nonce, &fixture.key)?;
        let context = operation_nonce_body(&fixture.operation, &nonce)?;
        chio_core::crypto::verify_wrapped_bytes(
            &fixture.key.public_key(),
            OPERATION_NONCE_SCHEMA,
            &context,
            &nonce.signature,
        )?;
        let mut wire: serde_json::Value =
            serde_json::from_slice(fixture.reservation.canonical_bytes())?;
        wire["signed_nonce"] = serde_json::to_value(nonce)?;
        let error = AdmissionExecutionNonceReservationV1::from_canonical_bytes(
            &canonical_json_bytes(&wire)?,
            &fixture.operation,
            &fixture.original,
            &fixture.key.public_key(),
            now_ms(),
        )
        .expect_err("retired nonce schema entered the public reservation decoder");
        assert_eq!(
            error,
            AdmissionOperationStoreError::Invariant(format!(
                "execution nonce has unsupported schema: expected chio.execution_nonce.v1, got {schema}"
            )),
            "{schema}"
        );
    }
    assert_eq!(
        fixture
            .fixture
            .store
            .load_by_operation_id(fixture.operation.binding().operation_id())?,
        Some(fixture.operation.clone())
    );

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
    upgraded.nonce.schema = "chio.operation_execution_nonce.v1".into();
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
