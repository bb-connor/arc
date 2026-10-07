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
    approval_required: bool,
    dpop_required: bool,
) -> TestResult {
    let profile = AdmissionAuthorityProfileV1::new(selection)?;
    let (kernel, admission, _, now) = super::fixture::caller_admission_with_profile(
        Some(&profile),
        approval_required,
        dpop_required,
    )?;
    assert_eq!(
        admission
            .operation
            .binding()
            .participant_requirements()
            .approval,
        approval_required,
    );
    let original = admission.original_retained_request().ok_or("original")?;
    original.validate_binding(admission.operation.binding())?;
    assert!(original.request_for_revalidation().approval_token.is_none());
    assert_eq!(original.matching_grants_require_dpop(), dpop_required);
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
    require_missing_custody_denial(selected, "runtime", false, false)
}

#[test]
fn caller_snapshot_rejects_missing_required_approval_custody() -> TestResult {
    require_missing_custody_denial(approval_selection()?, "approval", true, false)
}

#[test]
fn caller_snapshot_accepts_threshold_and_unused_cumulative_approval_custody() -> TestResult {
    use super::fixture::{caller_admission_with_approval, Approval};
    let profile = AdmissionAuthorityProfileV1::new(approval_selection()?)?;
    for approval in [
        Approval::Threshold,
        Approval::CumulativeThreshold,
        Approval::CumulativeUnused,
    ] {
        let (kernel, admission, _, now) =
            caller_admission_with_approval(Some(&profile), approval, false)?;
        let original = admission.original_retained_request().ok_or("original")?;
        original.validate_binding(admission.operation.binding())?;
        assert!(
            admission
                .operation
                .binding()
                .participant_requirements()
                .approval
        );
        assert!(original.request_for_revalidation().approval_token.is_none());
        assert!(original
            .request_for_revalidation()
            .approval_tokens
            .is_empty());
        let custody = kernel.read_caller_participant_custody(&admission, 0, now)?;
        assert_eq!(
            serde_json::to_value(custody)?,
            serde_json::json!({
                "runtime": null, "approval": null, "dpop": null,
            }),
            "{approval:?}"
        );
    }
    Ok(())
}

#[test]
fn caller_single_approval_missing_all_custody_artifacts_is_rejected() -> TestResult {
    let profile = AdmissionAuthorityProfileV1::new(approval_selection()?)?;
    let (kernel, mut admission, _, now) =
        super::fixture::caller_admission_with_profile(Some(&profile), true, false)?;
    // The single-token producer does not reserve a threshold approval set.
    assert!(admission.operation.threshold_proposal_hash().is_none());
    assert!(admission.operation.approval_set_hash().is_none());
    assert!(admission
        .operation
        .governed_approval_ledger_digest()
        .is_none());
    admission.operation = super::fixture::advance(
        admission.operation,
        vec![],
        AdmissionOperationState::CapturePending,
        now,
    )?;
    let error = kernel
        .read_caller_participant_custody(&admission, 0, now)
        .err()
        .ok_or("missing singular custody accepted")?;
    assert!(error
        .to_string()
        .contains("omitted its selected approval authority"));
    Ok(())
}

#[test]
fn cumulative_custody_requirement_ignores_unselected_grants_and_survives_retention() -> TestResult {
    use super::fixture::{caller_admission_with_approval, Approval};
    let (kernel, admission, mut request, _) =
        caller_admission_with_approval(None, Approval::Single, false)?;
    let original = admission.original_retained_request().ok_or("original")?;
    let mut body = request.capability.body();
    let mut unrelated = body.scope.grants[0].clone();
    unrelated.tool_name = "unselected-cumulative-tool".into();
    unrelated.constraints = vec![
        chio_core::capability::scope::Constraint::RequireCumulativeApprovalAbove {
            threshold: chio_core::capability::scope::MonetaryAmount {
                units: 100,
                currency: "USD".into(),
            },
            approval_budget_id: "unselected-budget".into(),
            approval_budget_epoch: 1,
            cumulative_approval_root_binding: None,
        },
    ];
    body.scope.grants.push(unrelated);
    request.capability =
        chio_core::capability::token::CapabilityToken::sign(body, &kernel.config.keypair)?;
    let matching = resolve_required_matching_grants(
        &request.capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        None,
    )?;
    let retained = RetainedToolAdmissionRequestV1::from_admission(
        &request,
        &matching,
        &[],
        None,
        original.authority_profile(),
    )?;
    retained.validate_request_material(&request)?;
    let restored =
        RetainedToolAdmissionRequestV1::from_canonical_bytes(retained.canonical_bytes())?;
    assert!(!restored.matching_grants_require_cumulative_approval());
    let (_, cumulative, _, _) =
        caller_admission_with_approval(None, Approval::CumulativeUnused, false)?;
    let retained = cumulative
        .original_retained_request()
        .ok_or("cumulative original")?;
    assert!(
        RetainedToolAdmissionRequestV1::from_canonical_bytes(retained.canonical_bytes())?
            .matching_grants_require_cumulative_approval()
    );
    Ok(())
}

fn approval_selection() -> TestResult<AdmissionAuthoritySelectionV1> {
    let mut selected = selection();
    selected.approval = Some(GovernedApprovalAuthorityBindingV1::new(
        identifier("approval")?,
        identifier("approval-generation")?,
    ));
    Ok(selected)
}

#[test]
fn caller_snapshot_allows_configured_but_unused_approval_authority() -> TestResult {
    require_absent_custody(Some(&AdmissionAuthorityProfileV1::new(
        approval_selection()?,
    )?))
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
    require_missing_custody_denial(dpop_selection()?, "DPoP", false, true)
}

#[test]
fn caller_snapshot_allows_configured_but_unused_dpop_authority() -> TestResult {
    require_absent_custody(Some(&AdmissionAuthorityProfileV1::new(dpop_selection()?)?))
}

fn require_absent_custody(profile: Option<&AdmissionAuthorityProfileV1>) -> TestResult {
    let (kernel, admission, _, now) =
        super::fixture::caller_admission_with_profile(profile, false, false)?;
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
