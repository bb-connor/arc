use super::*;
use crate::admission_operation::{ProviderAttemptBindingV1, StoreMutationFence};
use chio_core::canonical::canonical_json_bytes;

mod schema;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    kernel: Keypair,
    executor: Keypair,
    authorization: SignedCallerDispatchAuthorizationV1,
}

fn identifier(value: &str) -> TestResult<AdmissionIdentifier> {
    Ok(AdmissionIdentifier::try_new("test", value)?)
}

fn digest(value: &str) -> TestResult<AdmissionDigest> {
    Ok(AdmissionDigest::try_new(
        "test",
        sha256_hex(value.as_bytes()),
    )?)
}

fn fixture() -> TestResult<Fixture> {
    let kernel = Keypair::from_seed(&[41; 32]);
    let executor = Keypair::from_seed(&[42; 32]);
    let operation_id = AdmissionOperationId::from_persisted(sha256_hex(b"original-operation"))?;
    let body = CallerDispatchAuthorizationBodyV1 {
        schema: CALLER_DISPATCH_AUTHORIZATION_SCHEMA.into(),
        kernel_public_key: kernel.public_key(),
        executor: CallerExecutorIdentityV1 {
            executor_id: identifier("caller-worker")?,
            public_key: executor.public_key(),
            key_epoch: 7,
        },
        invocation: CallerInvocationBindingV1 {
            operation_id: operation_id.clone(),
            request_id: identifier("request")?,
            request_binding_hash: digest("request-binding")?,
            capability_id: identifier("capability")?,
            capability_digest: digest("capability")?,
            server_id: identifier("server")?,
            tool_name: identifier("mutate")?,
            parameters_digest: digest("parameters")?,
        },
        committed: CallerCommittedDispatchV1 {
            execution_nonce_id: identifier("nonce")?,
            budget_hold_id: identifier("hold")?,
            dispatch_commit: AdmissionDispatchCommitBindingV1 {
                committed_version: 9,
                dispatch_launch: Default::default(),
                coordinator_lease_id: identifier("coordinator")?,
                coordinator_lease_epoch: 3,
                store_fence: StoreMutationFence {
                    store_uuid: "authority".into(),
                    lease_id: "serving-owner".into(),
                    owner_epoch: 3,
                },
                provider_attempt: Some(ProviderAttemptBindingV1 {
                    operation_id: operation_id.as_str().into(),
                    attempt_id: "attempt".into(),
                    transport_id: "caller-report:server".into(),
                    transport_key_epoch: 7,
                }),
            },
            frozen_context_digest: digest("private-context")?,
        },
        not_before_unix_ms: 1_000,
        expires_at_unix_ms: 2_000,
    };
    let authorization = SignedCallerDispatchAuthorizationV1::sign(body, &kernel)?;
    Ok(Fixture {
        kernel,
        executor,
        authorization,
    })
}

fn verify<'a>(
    fixture: &Fixture,
    signed: &'a SignedCallerDispatchAuthorizationV1,
    now: u64,
) -> Result<VerifiedCallerDispatchAuthorization<'a>, CallerDeliveryError> {
    signed.verify_for_claim(
        &fixture.kernel.public_key(),
        &fixture.authorization.authorization.executor,
        &fixture.authorization.authorization.invocation,
        now,
    )
}

fn report(fixture: &Fixture) -> TestResult<SignedCallerDeliveryReportV1> {
    let digest = verify(fixture, &fixture.authorization, 1_100)?
        .digest()
        .clone();
    Ok(SignedCallerDeliveryReportV1::sign(
        CallerDeliveryReportBodyV1 {
            schema: CALLER_DELIVERY_REPORT_SCHEMA.into(),
            authorization_digest: digest,
            executor: fixture.authorization.authorization.executor.clone(),
            claim_id: identifier("durable-claim")?,
            execution_started_at_unix_ms: 1_100,
            completed_at_unix_ms: 3_000,
            output: serde_json::json!({"private_result": "not-for-diagnostics"}),
            realized_cost: Some(chio_core::capability::scope::MonetaryAmount {
                units: 3,
                currency: "USD".into(),
            }),
        },
        &fixture.executor,
    )?)
}

fn verify_report(
    fixture: &Fixture,
    report: &SignedCallerDeliveryReportV1,
) -> Result<(), CallerDeliveryError> {
    report.verify(
        &fixture.authorization,
        &fixture.kernel.public_key(),
        &fixture.authorization.authorization.executor,
        &fixture.authorization.authorization.invocation,
    )
}

#[test]
fn signed_start_round_trips_exactly_and_has_a_half_open_execution_interval() -> TestResult {
    let fixture = fixture()?;
    let bytes = fixture.authorization.canonical_bytes()?;
    let decoded = SignedCallerDispatchAuthorizationV1::from_canonical_bytes(&bytes)?;
    assert_eq!(decoded, fixture.authorization);
    for now in [1_000, 1_999] {
        let verified = verify(&fixture, &decoded, now)?;
        assert_eq!(verified.digest(), &digest(std::str::from_utf8(&bytes)?)?);
        assert_eq!(verified.authorization(), &decoded);
        assert_eq!(
            verified.require_live_at(2_000),
            Err(CallerDeliveryError::Expired)
        );
    }
    for now in [999, 2_000, 3_000] {
        assert!(verify(&fixture, &decoded, now).is_err());
    }
    Ok(())
}

#[test]
fn start_rejects_each_substituted_binding_and_unpinned_signer() -> TestResult {
    let fixture = fixture()?;
    let original = serde_json::to_value(&fixture.authorization)?;
    for (pointer, replacement) in [
        (
            "/authorization/schema",
            serde_json::json!(CALLER_DELIVERY_REPORT_SCHEMA),
        ),
        (
            "/authorization/kernel_public_key",
            serde_json::json!(fixture.executor.public_key()),
        ),
        (
            "/authorization/executor/executor_id",
            serde_json::json!("other-executor"),
        ),
        (
            "/authorization/executor/public_key",
            serde_json::json!(fixture.kernel.public_key()),
        ),
        ("/authorization/executor/key_epoch", serde_json::json!(8)),
        (
            "/authorization/invocation/request_id",
            serde_json::json!("other-request"),
        ),
        (
            "/authorization/invocation/operation_id",
            serde_json::json!(sha256_hex(b"other-operation")),
        ),
        (
            "/authorization/invocation/request_binding_hash",
            serde_json::json!(sha256_hex(b"other-request")),
        ),
        (
            "/authorization/invocation/capability_id",
            serde_json::json!("other-capability"),
        ),
        (
            "/authorization/invocation/capability_digest",
            serde_json::json!(sha256_hex(b"other-capability")),
        ),
        (
            "/authorization/invocation/server_id",
            serde_json::json!("other-server"),
        ),
        (
            "/authorization/invocation/tool_name",
            serde_json::json!("other-tool"),
        ),
        (
            "/authorization/invocation/parameters_digest",
            serde_json::json!(sha256_hex(b"other-parameters")),
        ),
        (
            "/authorization/committed/execution_nonce_id",
            serde_json::json!("other-nonce"),
        ),
        (
            "/authorization/committed/budget_hold_id",
            serde_json::json!("other-hold"),
        ),
        (
            "/authorization/committed/frozen_context_digest",
            serde_json::json!(sha256_hex(b"other-context")),
        ),
        (
            "/authorization/committed/dispatch_commit/committed_version",
            serde_json::json!(10),
        ),
        (
            "/authorization/committed/dispatch_commit/provider_attempt/attempt_id",
            serde_json::json!("other-attempt"),
        ),
        (
            "/authorization/committed/dispatch_commit/provider_attempt/transport_key_epoch",
            serde_json::json!(8),
        ),
        ("/authorization/not_before_unix_ms", serde_json::json!(900)),
        (
            "/authorization/expires_at_unix_ms",
            serde_json::json!(4_000),
        ),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).ok_or("mutation pointer")? = replacement;
        if let Ok(decoded) = SignedCallerDispatchAuthorizationV1::from_canonical_bytes(
            &canonical_json_bytes(&changed)?,
        ) {
            assert!(
                verify(&fixture, &decoded, 1_100).is_err(),
                "accepted {pointer}"
            );
        }
    }
    let mut forged = fixture.authorization.clone();
    forged.signature = fixture.executor.sign_wrapped(
        CALLER_DISPATCH_AUTHORIZATION_SCHEMA,
        &CanonicalBytes::from_serializable(&forged.authorization)?,
    )?;
    assert!(verify(&fixture, &forged, 1_100).is_err());
    Ok(())
}

#[test]
fn a_late_authenticated_report_does_not_renew_permission() -> TestResult {
    let fixture = fixture()?;
    let report = report(&fixture)?;
    verify_report(&fixture, &report)?;
    let decoded = SignedCallerDeliveryReportV1::from_canonical_bytes(&report.canonical_bytes()?)?;
    assert_eq!(decoded, report);
    assert!(verify(
        &fixture,
        &fixture.authorization,
        report.report.completed_at_unix_ms
    )
    .is_err());
    assert!(!format!("{report:?}").contains("not-for-diagnostics"));
    Ok(())
}

#[test]
fn reports_reject_rebinding_modified_output_cost_time_claim_and_other_executor() -> TestResult {
    let fixture = fixture()?;
    let report = report(&fixture)?;
    let original = serde_json::to_value(&report)?;
    for (pointer, replacement) in [
        (
            "/report/schema",
            serde_json::json!(CALLER_DISPATCH_AUTHORIZATION_SCHEMA),
        ),
        (
            "/report/authorization_digest",
            serde_json::json!(sha256_hex(b"other-authorization")),
        ),
        (
            "/report/executor/executor_id",
            serde_json::json!("other-executor"),
        ),
        (
            "/report/executor/public_key",
            serde_json::json!(fixture.kernel.public_key()),
        ),
        ("/report/executor/key_epoch", serde_json::json!(8)),
        ("/report/claim_id", serde_json::json!("other-claim")),
        (
            "/report/execution_started_at_unix_ms",
            serde_json::json!(1_200),
        ),
        ("/report/completed_at_unix_ms", serde_json::json!(4_000)),
        ("/report/output", serde_json::json!({"substituted": true})),
        ("/report/realized_cost/units", serde_json::json!(4)),
        ("/report/realized_cost/currency", serde_json::json!("EUR")),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).ok_or("mutation pointer")? = replacement;
        if let Ok(decoded) =
            SignedCallerDeliveryReportV1::from_canonical_bytes(&canonical_json_bytes(&changed)?)
        {
            assert!(
                verify_report(&fixture, &decoded).is_err(),
                "accepted {pointer}"
            );
        }
    }
    for started in [999, 2_000] {
        let mut body = report.report.clone();
        body.execution_started_at_unix_ms = started;
        let signed = SignedCallerDeliveryReportV1::sign(body, &fixture.executor)?;
        assert!(verify_report(&fixture, &signed).is_err());
    }
    let mut forged = report;
    forged.signature = fixture.kernel.sign_wrapped(
        CALLER_DELIVERY_REPORT_SCHEMA,
        &CanonicalBytes::from_serializable(&forged.report)?,
    )?;
    assert!(verify_report(&fixture, &forged).is_err());
    Ok(())
}

#[test]
fn authorization_and_report_refuse_unwrapped_and_foreign_id_signatures() -> TestResult {
    let fixture = fixture()?;
    for (label, signature) in crate::wrapper_refusals::refused_signatures(
        &fixture.kernel,
        &fixture.authorization.authorization,
    ) {
        let mut refused = fixture.authorization.clone();
        refused.signature = signature;
        assert!(
            matches!(
                verify(&fixture, &refused, 1_100),
                Err(CallerDeliveryError::Signature)
            ),
            "{label}"
        );
    }
    let report = report(&fixture)?;
    for (label, signature) in
        crate::wrapper_refusals::refused_signatures(&fixture.executor, &report.report)
    {
        let mut refused = report.clone();
        refused.signature = signature;
        assert_eq!(
            verify_report(&fixture, &refused),
            Err(CallerDeliveryError::Signature),
            "{label}"
        );
    }
    Ok(())
}

#[test]
fn codecs_reject_unknown_fields_noncanonical_bytes_unsafe_numbers_and_size_overflow() -> TestResult
{
    let fixture = fixture()?;
    let bytes = fixture.authorization.canonical_bytes()?;
    let mut padded = bytes.clone();
    padded.push(b' ');
    assert!(SignedCallerDispatchAuthorizationV1::from_canonical_bytes(&padded).is_err());
    let mut wire = serde_json::to_value(&fixture.authorization)?;
    wire["unknown"] = serde_json::json!(false);
    assert!(
        SignedCallerDispatchAuthorizationV1::from_canonical_bytes(&canonical_json_bytes(&wire)?)
            .is_err()
    );
    assert!(
        SignedCallerDispatchAuthorizationV1::from_canonical_bytes(&vec![
            b' ';
            MAX_AUTHORIZATION_BYTES + 1
        ])
        .is_err()
    );
    assert!(
        SignedCallerDeliveryReportV1::from_canonical_bytes(&vec![b' '; MAX_REPORT_BYTES + 1])
            .is_err()
    );
    for invalid in [0, MAX_SAFE_INTEGER + 1, u64::MAX] {
        let mut body = fixture.authorization.authorization.clone();
        body.executor.key_epoch = invalid;
        assert!(SignedCallerDispatchAuthorizationV1::sign(body, &fixture.kernel).is_err());
    }
    let mut body = report(&fixture)?.report;
    body.output = serde_json::json!({"too_large": "x".repeat(MAX_REPORT_BYTES)});
    assert!(SignedCallerDeliveryReportV1::sign(body, &fixture.executor).is_err());
    let mut body = fixture.authorization.authorization;
    body.schema = "reservation-is-not-start".into();
    assert!(SignedCallerDispatchAuthorizationV1::sign(body, &fixture.kernel).is_err());
    Ok(())
}

const TEMPORAL_GOLDEN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../sdks/python/chio-temporal/tests/fixtures/caller_delivery_golden_v1.json"
);

/// The chio-temporal interceptor's golden vector: the authorization, an
/// executor report over it and a mediated receipt, each from its signer.
fn temporal_golden() -> TestResult<String> {
    let fixture = fixture()?;
    let authorization = &fixture.authorization;
    let digest = verify(&fixture, authorization, 1_100)?.digest().clone();
    let report = SignedCallerDeliveryReportV1::sign(
        CallerDeliveryReportBodyV1 {
            schema: CALLER_DELIVERY_REPORT_SCHEMA.into(),
            authorization_digest: digest.clone(),
            executor: authorization.authorization.executor.clone(),
            claim_id: identifier("temporal:claim")?,
            execution_started_at_unix_ms: 1_100,
            completed_at_unix_ms: 1_200,
            output: serde_json::json!({
                "outcome": "completed",
                "result_sha256": sha256_hex(b"result"),
            }),
            realized_cost: None,
        },
        &fixture.executor,
    )?;
    let parameters = serde_json::json!({"args": ["x", 1]});
    let body: chio_core::receipt::body::ChioReceiptBody =
        serde_json::from_value(serde_json::json!({
            "id": "temporal-golden",
            "timestamp": 1_700_000_000_u64,
            "capability_id": "capability",
            "tool_server": "server",
            "tool_name": "mutate",
            "action": {
                "parameters": parameters,
                "parameter_hash": sha256_hex(&canonical_json_bytes(&parameters)?),
            },
            "decision": {"verdict": "allow"},
            "receipt_kind": "mediated_decision",
            "boundary_class": "prevent",
            "tool_origin": "caller_executed",
            "redaction_mode": "none",
            "content_hash": sha256_hex(b"content"),
            "policy_hash": sha256_hex(b"policy"),
            "trust_level": "mediated",
            "kernel_key": fixture.kernel.public_key(),
        }))?;
    let receipt = chio_core::receipt::body::ChioReceipt::sign(body, &fixture.kernel)?;
    let golden = serde_json::json!({
        "authorization": authorization,
        "authorization_body_canonical":
            String::from_utf8(canonical_json_bytes(&authorization.authorization)?)?,
        "authorization_canonical": String::from_utf8(authorization.canonical_bytes()?)?,
        "authorization_digest": digest.as_str(),
        "executor_seed_byte": 42,
        "generator": "chio-kernel caller_delivery fixture (seeds 0x29 kernel, 0x2a executor): \
            SignedCallerDispatchAuthorizationV1::sign, SignedCallerDeliveryReportV1::sign, \
            ChioReceipt::sign",
        "kernel_seed_byte": 41,
        "receipt": receipt,
        "report": report,
        "report_body_canonical": String::from_utf8(canonical_json_bytes(&report.report)?)?,
    });
    let sorted: serde_json::Value = serde_json::from_slice(&canonical_json_bytes(&golden)?)?;
    Ok(format!("{}\n", serde_json::to_string_pretty(&sorted)?))
}

/// Set `CHIO_WRITE_TEMPORAL_GOLDEN=1` to rewrite the committed chio-temporal
/// golden vector from this generator.
#[test]
fn temporal_golden_is_the_generator_output() -> TestResult {
    let generated = temporal_golden()?;
    if std::env::var_os("CHIO_WRITE_TEMPORAL_GOLDEN").is_some() {
        std::fs::write(TEMPORAL_GOLDEN, &generated)?;
    }
    assert_eq!(std::fs::read_to_string(TEMPORAL_GOLDEN)?, generated);
    Ok(())
}
