use super::*;
use crate::admission_operation_store::raw_liability_test_support::{
    raw_source_refuses_after_control, RawLiabilitySourceControl,
};

#[test]
fn raw_price_rejects_another_transaction_and_changed_original_or_claim(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture();
    let begun = now_ms();
    let operation = committed(&fixture, "raw-source-original", begun);
    let at = begun + 20;
    let (blob, outcome) = returned_value(
        &operation,
        fixture.fence.clone(),
        at,
        serde_json::json!({"source": "original Raw custody"}),
        None,
    )?;
    let claimant = id("claimant_id", "tool-outcome-worker");
    let claim = RecoveryClaimRequest {
        operation_id: operation.binding().operation_id(),
        expected_version: operation.version(),
        claimant_id: &claimant,
        expires_at_unix_ms: at + 60_000,
        fence: &fixture.fence,
    };
    for control in [
        RawLiabilitySourceControl::DifferentTransaction,
        RawLiabilitySourceControl::OriginalChanged,
        RawLiabilitySourceControl::ClaimChanged,
    ] {
        assert!(raw_source_refuses_after_control(
            &fixture.operations,
            &operation,
            &blob,
            &outcome,
            &claim,
            at + 1,
            control,
        )?);
    }
    assert_eq!(
        fixture
            .operations
            .load_by_operation_id(operation.binding().operation_id())?,
        Some(operation.clone())
    );
    assert!(fixture
        .outcomes
        .lookup_by_operation(claim.operation_id)?
        .is_none());
    Ok(())
}

#[test]
fn raw_price_rejects_unpriced_indexes_and_temporary_callbacks(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture();
    let begun = now_ms();
    let operation = committed(&fixture, "raw-source-catalog", begun);
    let at = begun + 20;
    let (blob, outcome) = returned_value(
        &operation,
        fixture.fence.clone(),
        at,
        serde_json::json!({"source": "Raw catalog"}),
        None,
    )?;
    let claimant = id("claimant_id", "tool-outcome-worker");
    let claim = RecoveryClaimRequest {
        operation_id: operation.binding().operation_id(),
        expected_version: operation.version(),
        claimant_id: &claimant,
        expires_at_unix_ms: at + 60_000,
        fence: &fixture.fence,
    };
    for control in [
        RawLiabilitySourceControl::ExtraIndex,
        RawLiabilitySourceControl::TemporaryCallback,
    ] {
        assert!(raw_source_refuses_after_control(
            &fixture.operations,
            &operation,
            &blob,
            &outcome,
            &claim,
            at + 1,
            control,
        )?);
    }
    assert!(fixture
        .outcomes
        .lookup_by_operation(claim.operation_id)?
        .is_none());
    Ok(())
}

#[test]
fn raw_price_refuses_a_conflicting_live_claimant_before_any_custody_write(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::admission_operation_store::raw_liability_test_support::whole_raw_custody_wal_price_before_write;
    let fixture = fixture();
    let begun = now_ms();
    let operation = committed(&fixture, "raw-live-claim", begun);
    let at = begun + 20;
    let (blob, outcome) = returned_value(
        &operation,
        fixture.fence.clone(),
        at,
        serde_json::json!({"source":"live claim owner"}),
        None,
    )?;
    let claimant = id("claimant_id", "tool-outcome-worker");
    let competing = id("claimant_id", "another-raw-claimant");
    let claim = RecoveryClaimRequest {
        operation_id: operation.binding().operation_id(),
        expected_version: operation.version(),
        claimant_id: &claimant,
        expires_at_unix_ms: at + 60_000,
        fence: &fixture.fence,
    };
    assert!(
        whole_raw_custody_wal_price_before_write(
            &fixture.operations,
            &operation,
            &blob,
            &outcome,
            &claim,
            at + 1
        )? > 0
    );
    let other = RecoveryClaimRequest {
        claimant_id: &competing,
        ..claim
    };
    assert!(matches!(
        whole_raw_custody_wal_price_before_write(
            &fixture.operations,
            &operation,
            &blob,
            &outcome,
            &other,
            at + 1
        ),
        Err(AdmissionOperationStoreError::Fenced)
    ));
    assert!(fixture
        .outcomes
        .lookup_by_operation(claim.operation_id)?
        .is_none());
    assert_eq!(
        fixture
            .operations
            .load_by_operation_id(claim.operation_id)?,
        Some(operation.clone())
    );
    Ok(())
}
