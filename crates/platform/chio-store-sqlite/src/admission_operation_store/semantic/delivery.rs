//! Current outward disclosure, separate from private captured-effect settlement.
use super::*;
use chio_kernel::admission_operation::RetainedToolAdmissionRequestV1;

pub(super) fn require_current_delivery(
    tx: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    original: &RetainedToolAdmissionRequestV1,
    captured: &NativeSemanticCaptureRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    if !matches!(
        operation.state(),
        AdmissionOperationState::Completed | AdmissionOperationState::DeniedAfterDelivery
    ) {
        return Err(refused(
            "current semantic delivery requires terminal custody",
        ));
    }
    let evidence = output::authenticated_native_output_influence(
        tx,
        operation,
        original,
        &captured.native_authority,
    )?
    .ok_or_else(|| refused("semantic delivery lost original custody"))?;
    let disposition = captured.invocation.action.output;
    if evidence.output_disposition() != disposition || evidence.influence().unknown {
        return Err(refused("semantic delivery has an unproved origin"));
    }
    let audience = if disposition == SemanticOutputDispositionV1::Withhold {
        let audience = evidence
            .withheld_status_audience()
            .ok_or_else(|| refused("withheld status has no authored audience"))?;
        if !evidence.output_label().flows_to(audience) {
            return Err(refused("withheld status classification changed"));
        }
        Some(audience)
    } else {
        None
    };
    // Ordinary public replay has already matched the actual trusted native
    // authority and complete caller identity to the original admission binding.
    // These retained selectors therefore address that same current recipient.
    // Scoped recovery release independently joins its actor's current labels.
    let (current, _) = crate::security_state::observe_native_flow_state(
        tx,
        captured.native_authority.security_authority_id().as_str(),
        &recovery_flow_key(&captured.security_context),
    )
    .map_err(refused)?;
    let current = current.ok_or_else(|| refused("semantic delivery source absent"))?;
    for label in [
        &current.principal_label,
        &current.lineage_label,
        &current.session_label,
    ] {
        if !evidence.output_label().flows_to(label)
            || audience.is_some_and(|audience| !audience.flows_to(label))
        {
            return Err(refused("semantic delivery is below its verified source"));
        }
    }
    Ok(())
}
