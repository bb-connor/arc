//! Owner-connection corruption reaches the private selector guards.
//! Synthetic hold index slots are not claimed legitimate duplicate admissions.
use super::*;
use chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1;
use chio_kernel::supplemental_admission::SupplementalAdmissionAuthorityBindingV1;

const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn selections(
    fixture: &Fixture,
) -> AnchoredTestResult<(
    NativeSecurityAuthorityBindingV1,
    SupplementalAdmissionAuthorityBindingV1,
)> {
    Ok((
        NativeSecurityAuthorityBindingV1::new(
            AdmissionIdentifier::try_new("store", fixture.fence.store_uuid.clone())?,
            AdmissionIdentifier::try_new("authority", "selector-query-test")?,
            AdmissionDigest::try_new("initialization", "b".repeat(64))?,
        ),
        SupplementalAdmissionAuthorityBindingV1::new(
            AdmissionIdentifier::try_new("participant", "selector-participant")?,
            AdmissionDigest::try_new("configuration", "c".repeat(64))?,
            AdmissionIdentifier::try_new("verifier", "selector-verifier")?,
            AdmissionDigest::try_new("configuration", "d".repeat(64))?,
        ),
    ))
}

fn select(
    fixture: &Fixture,
) -> AnchoredTestResult<
    Result<Option<RetainedToolAdmissionCustodySnapshot>, AdmissionOperationStoreError>,
> {
    let (native, participant) = selections(fixture)?;
    Ok(fixture
        .store
        .load_retained_tool_admission_custody_by_supplemental_artifact(
            DIGEST,
            &native,
            &participant,
            &fixture.fence,
            now_ms(),
        ))
}

fn seed_hold(fixture: &Fixture, name: &str) -> AnchoredTestResult {
    // Deliberate owner-connection corruption setup, not an admitted hold.
    // The empty supplemental selector was already proved healthy above.
    let connection = fixture.store.connection()?;
    let at = i64::try_from(now_ms())?;
    assert_eq!(
        connection.execute(
            "INSERT INTO budget_authorization_holds
         (hold_id, capability_id, grant_index, authorized_exposure_units,
          remaining_exposure_units, invocation_count_debited, invocation_captured,
          disposition, created_at, updated_at)
         VALUES (?1, ?1, 0, 0, 0, 0, 0, 'open', ?2, ?2)",
            params![name, at],
        )?,
        1
    );
    Ok(())
}

#[test]
fn owner_connection_index_damage_reaches_the_exact_index_validator() -> AnchoredTestResult {
    let fixture = fixture();
    assert!(matches!(select(&fixture)?, Ok(None)));
    {
        let connection = fixture.store.connection()?;
        connection.execute_batch(
            "DROP INDEX idx_budget_holds_supplemental_artifact;
             CREATE INDEX idx_budget_holds_supplemental_artifact ON budget_authorization_holds(operation_id, supplemental_artifact_digest) WHERE supplemental_artifact_digest IS NOT NULL;",
        )?;
        assert!(matches!(
            crate::budget_store::SqliteBudgetStore::verify_supplemental_artifact_selector_index(&connection),
            Err(chio_kernel::budget_store::BudgetStoreError::Invariant(ref reason)) if reason == "supplemental artifact selector index definition differs"
        ));
    }
    assert!(matches!(
        select(&fixture)?,
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    Ok(())
}

#[test]
fn owner_connection_oversized_slot_reaches_the_bounded_id_guard() -> AnchoredTestResult {
    let fixture = fixture();
    assert!(matches!(select(&fixture)?, Ok(None)));
    seed_hold(&fixture, "oversized-selector-slot")?;
    {
        let connection = fixture.store.connection()?;
        assert_eq!(connection.execute(
            "UPDATE budget_authorization_holds SET operation_id = ?1, supplemental_artifact_digest = ?2 WHERE hold_id = ?3",
            params!["x".repeat(513), DIGEST, "oversized-selector-slot"],
        )?, 1);
    }
    assert!(matches!(
        select(&fixture)?,
        Err(AdmissionOperationStoreError::Invariant(ref reason)) if reason == "supplemental selector operation ID exceeds bounds"
    ));
    Ok(())
}

#[test]
fn owner_connection_two_corrupt_slots_reach_the_ambiguity_guard() -> AnchoredTestResult {
    let fixture = fixture();
    assert!(matches!(select(&fixture)?, Ok(None)));
    seed_hold(&fixture, "selector-slot-a")?;
    seed_hold(&fixture, "selector-slot-z")?;
    {
        let connection = fixture.store.connection()?;
        for (hold, operation) in [
            ("selector-slot-a", "a-query-original"),
            ("selector-slot-z", "z-query-original"),
        ] {
            assert_eq!(connection.execute(
                "UPDATE budget_authorization_holds SET operation_id = ?1, supplemental_artifact_digest = ?2 WHERE hold_id = ?3",
                params![operation, DIGEST, hold],
            )?, 1);
        }
    }
    assert!(matches!(
        select(&fixture)?,
        Err(AdmissionOperationStoreError::Invariant(ref reason)) if reason == "supplemental authorization artifact has multiple original operations"
    ));
    Ok(())
}
