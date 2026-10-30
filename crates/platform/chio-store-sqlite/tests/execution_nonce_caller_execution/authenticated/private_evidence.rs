//! Private signed delivery evidence is mandatory for retained caller reports.
use super::*;
use chio_kernel::tool_outcome::{
    InvocationOutputV1, RawInvocationOutcomeV1, ToolOutcomeError, ToolOutcomeStore,
};
use chio_store_sqlite::caller_execution_ledger::SqliteCallerExecutionLedger;

#[test]
fn private_delivery_evidence_rejects_tampering_and_schema_confusion() -> TestResult {
    let (fixture, key) = fixture()?;
    let runtime = fixture.open()?;
    let request = reserve(&fixture, &runtime, "private-delivery-evidence")?;
    let authorization = start(&runtime, &request)?;
    let ledger = SqliteCallerExecutionLedger::provision(
        &fixture.directory.path().join("executor.db"),
        fixture.caller_executor.clone().ok_or("executor")?,
        2,
    )?;
    let report = ledger.execute_once(
        &authorization,
        &fixture.signer.public_key(),
        &authorization.authorization.invocation,
        &key,
        || Ok(crate::report()),
    )?;
    let response = runtime
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
    assert_eq!(response.verdict, Verdict::Allow);
    let raw = runtime
        .authority
        .tool_outcome_store()
        .load_raw_invocation_by_operation(&authorization.authorization.invocation.operation_id)?
        .ok_or("retained raw report")?;
    let persisted = raw.to_persisted();
    assert!(persisted.caller_delivery_evidence.is_some());
    assert_eq!(
        RawInvocationOutcomeV1::from_persisted(persisted.clone())?
            .canonical_blob()?
            .bytes(),
        raw.canonical_blob()?.bytes()
    );
    for change in [
        "missing",
        "schema",
        "signature",
        "output",
        "elapsed",
        "attempt",
        "commit",
    ] {
        let mut altered = persisted.clone();
        match change {
            "missing" => altered.caller_delivery_evidence = None,
            "schema" => {
                altered.schema = "chio.raw-invocation-outcome-with-signing-identity.v1".into()
            }
            "signature" => {
                altered
                    .caller_delivery_evidence
                    .as_mut()
                    .ok_or("evidence")?
                    .report
                    .signature = Keypair::generate().sign_exempt(
                    chio_core::crypto::ExemptFormat::JwsSigningInput,
                    b"different",
                )
            }
            "output" => {
                altered.output = InvocationOutputV1::Value {
                    value: serde_json::json!({"different": true}),
                }
            }
            "elapsed" => altered.elapsed_millis += 1,
            "attempt" => altered.provider_attempt.attempt_id.push_str("-different"),
            "commit" => altered.dispatch_operation_version += 1,
            _ => unreachable!(),
        }
        let expected = if change == "schema" {
            ToolOutcomeError::Invalid("raw.schema")
        } else {
            ToolOutcomeError::Binding("raw.caller_delivery_evidence")
        };
        assert_eq!(
            RawInvocationOutcomeV1::from_persisted(altered),
            Err(expected),
            "{change}",
        );
    }
    let public_receipt = String::from_utf8(canonical(&response.receipt)?)?;
    assert!(!public_receipt.contains(&serde_json::to_string(&report.signature)?));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
