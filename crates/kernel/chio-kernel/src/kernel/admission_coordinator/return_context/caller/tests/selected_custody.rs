//! In-memory capture rejects missing selected participants before publishing a
//! caller snapshot. These models do not claim physical ledger provenance.

use super::*;
use crate::admission_operation::governed_approval_claim::GovernedApprovalAuthorityBindingV1;
use crate::admission_operation::runtime_participant::RuntimeParticipantAuthorityBindingV1;
use crate::admission_operation::{AdmissionAuthorityProfileV1, AdmissionAuthoritySelectionV1};
use crate::dpop::authority::{DpopReplayAuthorityInputV1, DpopReplayAuthorityV1};

fn identifier(value: &str) -> TestResult<AdmissionIdentifier> {
    Ok(AdmissionIdentifier::try_new("authority", value)?)
}

fn selection() -> AdmissionAuthoritySelectionV1 {
    AdmissionAuthoritySelectionV1 {
        runtime_hook_installed: false,
        swarm_admission_required: false,
        runtime_enforces_swarm_authority: false,
        runtime_requires_dispatch_revalidation: false,
        runtime: None,
        approval: None,
        dpop: None,
    }
}

fn require_missing_custody_denial(
    selection: AdmissionAuthoritySelectionV1,
    family: &str,
    dpop_required: bool,
) -> TestResult {
    let profile = AdmissionAuthorityProfileV1::new(selection)?;
    let (kernel, admission, _, now) =
        super::fixture::caller_admission_with_profile(Some(&profile), dpop_required)?;
    let error = match kernel.read_caller_participant_custody(&admission, 0, now) {
        Ok(_) => {
            return Err(
                format!("published caller snapshot without selected {family} custody").into(),
            )
        }
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains(&format!("omitted its selected {family} authority")),
        "expected missing-custody denial, received {error}"
    );
    Ok(())
}

#[test]
fn caller_snapshot_rejects_missing_selected_runtime_custody() -> TestResult {
    let mut selected = selection();
    selected.runtime_hook_installed = true;
    selected.runtime_requires_dispatch_revalidation = true;
    selected.runtime = Some(RuntimeParticipantAuthorityBindingV1::new(
        identifier("runtime")?,
        identifier("runtime-generation")?,
    ));
    require_missing_custody_denial(selected, "runtime", false)
}

#[test]
fn caller_snapshot_allows_configured_but_unused_approval_authority() -> TestResult {
    let mut selected = selection();
    selected.approval = Some(GovernedApprovalAuthorityBindingV1::new(
        identifier("approval")?,
        identifier("approval-generation")?,
    ));
    require_absent_custody(Some(&AdmissionAuthorityProfileV1::new(selected)?))
}

fn dpop_selection() -> TestResult<AdmissionAuthoritySelectionV1> {
    let mut selected = selection();
    selected.dpop = Some(DpopReplayAuthorityV1::new(DpopReplayAuthorityInputV1 {
        destination_store_uuid: identifier("11111111-1111-4111-8111-111111111111")?,
        dpop_authority_id: identifier("dpop")?,
        expectation_id: AdmissionDigest::try_new("dpop generation", "a".repeat(64))?,
        proof_ttl_secs: 60,
        max_clock_skew_secs: 30,
    })?);
    Ok(selected)
}

#[test]
fn caller_snapshot_rejects_missing_required_dpop_custody() -> TestResult {
    require_missing_custody_denial(dpop_selection()?, "DPoP", true)
}

#[test]
fn caller_snapshot_allows_configured_but_unused_dpop_authority() -> TestResult {
    require_absent_custody(Some(&AdmissionAuthorityProfileV1::new(dpop_selection()?)?))
}

fn require_absent_custody(profile: Option<&AdmissionAuthorityProfileV1>) -> TestResult {
    let (kernel, admission, _, now) =
        super::fixture::caller_admission_with_profile(profile, false)?;
    let snapshot = kernel.read_caller_participant_custody(&admission, 0, now)?;
    assert_eq!(
        serde_json::to_value(snapshot)?,
        serde_json::json!({
            "runtime": null, "approval": null, "dpop": null
        })
    );
    Ok(())
}

#[test]
fn caller_snapshot_preserves_genuinely_unselected_and_legacy_custody_absence() -> TestResult {
    let explicit_absence = AdmissionAuthorityProfileV1::new(selection())?;
    for profile in [None, Some(&explicit_absence)] {
        require_absent_custody(profile)?;
    }
    Ok(())
}
