//! Actual captured-native store refusal before retaining or releasing output.
use super::*;
use chio_kernel::budget_store::BudgetQuotaKey;
use chio_kernel::tool_outcome::{
    RawInvocationOutcomeV1, RAW_INVOCATION_OUTCOME_WITH_SIGNING_IDENTITY_SCHEMA,
};
use chio_kernel::BudgetStore;

#[test]
fn native_raw_store_rejects_substituted_original_dispatch_bindings() -> TestResult {
    for egress in [false, true] {
        let mut fixture = Fixture::new(std::array::from_fn(|_| InformationLabel::bottom()))?;
        let captured = run_capture_through_with_clearance(
            &mut fixture,
            egress,
            InformationLabel::bottom(),
            |fixture| {
                Ok(fixture
                    .kernel
                    .evaluate_tool_call_blocking_with_security_context(
                        &fixture.request,
                        &fixture.context,
                    )?)
            },
        )?;
        let store = fixture.authority.admission_operation_store();
        let outcomes = fixture.authority.tool_outcome_store();
        let fence = fixture.authority.mutation_fence();
        let operation = store
            .load_by_operation_id(&captured.operation_id)?
            .ok_or("captured original operation")?;
        assert_eq!(
            operation.state(),
            AdmissionOperationState::DispatchCommitted
        );
        let ledger = store
            .load_native_dispatch_ledger(&captured.operation_id, &fence, now_ms()?)?
            .ok_or("captured original ledger")?;
        let ledger_value: serde_json::Value = serde_json::from_slice(&ledger.canonical_record)?;
        let context: SecurityInvocationContext =
            serde_json::from_value(ledger_value["context"].clone())?;
        let claimant: String =
            rusqlite::Connection::open(fixture._directory.path().join("admission.db"))?.query_row(
                "SELECT recovery_claimant_id FROM admission_operations WHERE operation_id = ?1",
                [captured.operation_id.as_str()],
                |row| row.get(0),
            )?;
        let now = now_ms()?;
        let lease = store.claim_recovery(
            &captured.operation_id,
            operation.version(),
            &AdmissionIdentifier::try_new("claimant", claimant)?,
            now,
            now + 60_000,
            &fence,
        )?;
        let (correct, correct_record) = test_support::native_returned_value(
            &operation,
            fence.clone(),
            now_ms()?,
            test_support::NativeReturnedValueContext {
                request: &fixture.request,
                security_context: &context,
                ledger: &ledger,
                receipt_signing_public_key: fixture.kernel.receipt_signing_public_key(),
                receipt_crypto_floor:
                    chio_core::receipt::crypto_floor::ReceiptCryptoFloor::AllowClassical,
            },
            serde_json::json!({"original_output": true}),
        )?;
        let original = RawInvocationOutcomeV1::from_canonical_bytes(correct.bytes())?;
        let before = snapshot(&fixture, &captured.operation_id)?;
        for substitution in ["id", "full_hash", "ledger", "context", "request", "missing"] {
            let mut value = serde_json::to_value(original.to_persisted())?;
            match substitution {
                "id" => {
                    value["original_security_dispatch_binding"]["dispatch_commitment_id"] =
                        serde_json::json!(format!("dispatch-commitment:{}", "0".repeat(64)))
                }
                "full_hash" => {
                    value["original_security_dispatch_binding"]["live_request_digest"] =
                        serde_json::json!("0".repeat(64))
                }
                "ledger" => {
                    value["original_security_dispatch_binding"]["native_dispatch_ledger_digest"] =
                        serde_json::json!("0".repeat(64))
                }
                "context" => {
                    let changed = SecurityInvocationContext::v1(
                        context.as_v1().clone().with_flow_state_generation(
                            context
                                .as_v1()
                                .flow_state_generation()
                                .ok_or("original flow generation")?
                                + 1,
                        ),
                    );
                    value["security_invocation_context"] = serde_json::to_value(changed)?;
                }
                "request" => {
                    let mut changed: chio_kernel::ToolCallRequest = serde_json::from_str(
                        value["request_canonical_json"]
                            .as_str()
                            .ok_or("retained request")?,
                    )?;
                    changed.arguments = serde_json::json!({"substituted_parameters": true});
                    value["request_canonical_json"] = serde_json::json!(String::from_utf8(
                        chio_core::canonical::canonical_json_bytes(&changed)?,
                    )?);
                }
                _ => {
                    value
                        .as_object_mut()
                        .ok_or("raw object")?
                        .remove("original_security_dispatch_binding");
                    value["schema"] =
                        serde_json::json!(RAW_INVOCATION_OUTCOME_WITH_SIGNING_IDENTITY_SCHEMA);
                }
            }
            // Every forged candidate is structurally canonical. The physical
            // original ledger, rather than a DTO decoder, must refuse it.
            let raw = RawInvocationOutcomeV1::from_canonical_bytes(
                &chio_core::canonical::canonical_json_bytes(&value)?,
            )?;
            let blob = raw.canonical_blob()?;
            let record =
                test_support::record_returned_blob(&operation, &blob, fence.clone(), now_ms()?)?;
            assert!(
                outcomes
                    .record_tool_returned(&operation, &lease, &blob, &record, &fence, now_ms()?,)
                    .is_err(),
                "egress={egress} substitution={substitution}"
            );
            assert_eq!(snapshot(&fixture, &captured.operation_id)?, before);
            assert_eq!(
                store.load_by_operation_id(&captured.operation_id)?,
                Some(operation.clone())
            );
            assert!(outcomes
                .lookup_by_operation(&captured.operation_id)?
                .is_none());
            assert_eq!(
                store.load_native_dispatch_ledger(&captured.operation_id, &fence, now_ms()?,)?,
                Some(ledger.clone())
            );
        }
        // Both an actual no-egress capture and actual committed egress accept
        // only the complete original tuple, without recapturing invocation.
        let (_, finalizing) = outcomes
            .record_tool_returned(
                &operation,
                &lease,
                &correct,
                &correct_record,
                &fence,
                now_ms()?,
            )?
            .into_parts();
        assert_eq!(finalizing.state(), AdmissionOperationState::Finalizing);
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
        assert_eq!(quota(&fixture)?, (0, 1));
        assert_eq!(snapshot(&fixture, &captured.operation_id)?.1, (0, 0));
    }
    Ok(())
}

fn quota(fixture: &Fixture) -> TestResult<(u32, u32)> {
    let usage = fixture
        .authority
        .budget_store()
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(&fixture.request.capability.id, 0))?
        .ok_or("original captured quota")?;
    Ok((usage.reserved_invocations, usage.captured_invocations))
}

type Snapshot = ((u32, u32), (i64, i64), i64);

fn snapshot(
    fixture: &Fixture,
    operation: &chio_kernel::admission_operation::AdmissionOperationId,
) -> TestResult<Snapshot> {
    let connection = rusqlite::Connection::open_with_flags(
        fixture._directory.path().join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let rows: (i64, i64, i64) = connection.query_row(
        "SELECT (SELECT COUNT(*) FROM security_participant_output_events WHERE operation_id = ?1),
                (SELECT COUNT(*) FROM tool_outcome_security_releases WHERE operation_id = ?1),
                (SELECT COUNT(*) FROM admission_operation_commits WHERE operation_id = ?1)",
        [operation.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    Ok((quota(fixture)?, (rows.0, rows.1), rows.2))
}

// Cloned retained readback supplies structural data, never a capture permit.
fn retained_native_ledger_diagnostic_refusal(kind: &str) -> TestResult {
    use chio_kernel::admission_operation::{
        AdmissionOperationError, AdmissionOperationStoreError,
        NativeSecurityDispatchRequestBindingV1,
    };
    use std::error::Error;
    let mut fixture = Fixture::new(std::array::from_fn(|_| InformationLabel::bottom()))?;
    let captured = run_capture_through_with_clearance(
        &mut fixture,
        false,
        InformationLabel::bottom(),
        |fixture| {
            Ok(fixture
                .kernel
                .evaluate_tool_call_blocking_with_security_context(
                    &fixture.request,
                    &fixture.context,
                )?)
        },
    )?;
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let ledger = store
        .load_native_dispatch_ledger(&captured.operation_id, &fence, now_ms()?)?
        .ok_or("actual retained native ledger")?;
    let original: serde_json::Value = serde_json::from_slice(&ledger.canonical_record)?;
    let context: SecurityInvocationContext = serde_json::from_value(original["context"].clone())?;
    assert!(NativeSecurityDispatchRequestBindingV1::from_ledger(&ledger, &context)?.is_some());
    let before = snapshot(&fixture, &captured.operation_id)?;
    let before_operation = store.load_by_operation_id(&captured.operation_id)?;
    let mut malformed = ledger.clone();
    let expected_code = if kind == "utf8" {
        malformed.canonical_record = vec![b'{', 0xff, b'}'];
        "urn:chio:error:attest:signed-json-not-utf8"
    } else if kind == "signed_input" {
        malformed.canonical_record = b"{\"schema\":0,".to_vec();
        malformed
            .canonical_record
            .extend_from_slice(&ledger.canonical_record[1..]);
        "urn:chio:error:attest:signed-json-invalid-input"
    } else {
        let mut value = original;
        value[kind] = serde_json::json!(7);
        malformed.canonical_record = chio_core::canonical::canonical_json_bytes(&value)?;
        malformed.record_digest = chio_kernel::admission_operation::AdmissionDigest::try_new(
            "diagnostic_clone_digest",
            chio_core::sha256_hex(&malformed.canonical_record),
        )?;
        "urn:chio:error:attest:signed-json-invalid-shape"
    };
    let error = NativeSecurityDispatchRequestBindingV1::from_ledger(&malformed, &context)
        .err()
        .ok_or("malformed retained ledger must refuse")?;
    // Check refusal and unchanged effects before the missing diagnostic owner.
    assert_eq!(snapshot(&fixture, &captured.operation_id)?, before);
    assert_eq!(
        store.load_by_operation_id(&captured.operation_id)?,
        before_operation
    );
    assert_eq!(
        store.load_native_dispatch_ledger(&captured.operation_id, &fence, now_ms()?)?,
        Some(ledger)
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert!(
        matches!(
            &error,
            AdmissionOperationStoreError::Operation(AdmissionOperationError::UntrustedInput(_))
        ),
        "retained ledger failure must keep its existing typed owner"
    );
    assert!(error.to_string().contains(expected_code));
    let mut source = error.source();
    let mut native = false;
    while let Some(cause) = source {
        native |= match kind {
            "utf8" => cause
                .downcast_ref::<std::str::Utf8Error>()
                .is_some_and(|error| error.valid_up_to() == 1 && error.error_len() == Some(1)),
            "signed_input" => matches!(
                cause.downcast_ref::<chio_core::Error>(),
                Some(chio_core::Error::CanonicalJson(_))
            ),
            _ => cause
                .downcast_ref::<serde_json::Error>()
                .is_some_and(serde_json::Error::is_data),
        };
        source = cause.source();
    }
    assert!(
        native,
        "retained ledger refusal must keep its concrete native source kind"
    );
    Ok(())
}

#[test]
fn native_original_ledger_reader_preserves_utf8_source_without_authority() -> TestResult {
    retained_native_ledger_diagnostic_refusal("utf8")
}
#[test]
fn native_original_ledger_reader_preserves_signed_input_source_without_authority() -> TestResult {
    retained_native_ledger_diagnostic_refusal("signed_input")
}
#[test]
fn native_original_ledger_reader_preserves_operation_serde_source_without_authority() -> TestResult
{
    retained_native_ledger_diagnostic_refusal("operation")
}
#[test]
fn native_original_ledger_reader_preserves_commitment_serde_source_without_authority() -> TestResult
{
    retained_native_ledger_diagnostic_refusal("original_dispatch_commitment_id")
}
#[test]
fn native_original_ledger_reader_preserves_digest_serde_source_without_authority() -> TestResult {
    retained_native_ledger_diagnostic_refusal("live_request_digest")
}
