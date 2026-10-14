//! Current outward disclosure, separate from private captured-effect settlement.
use super::*;
use chio_kernel::admission_operation::RetainedToolAdmissionRequestV1;

/// The first gate that decides current outward disclosure of a committed return.
/// Custody and binding failures are errors, never gates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SemanticDeliveryGate {
    Open,
    UnprovedOrigin,
    StatusAudienceAbsent,
    StatusClassificationChanged,
    SourceAbsent,
    BelowVerifiedSource,
}

impl SemanticDeliveryGate {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::UnprovedOrigin => "unproved-origin",
            Self::StatusAudienceAbsent => "status-audience-absent",
            Self::StatusClassificationChanged => "status-classification-changed",
            Self::SourceAbsent => "source-absent",
            Self::BelowVerifiedSource => "below-verified-source",
        }
    }
}

pub(super) fn require_current_delivery(
    tx: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    original: &RetainedToolAdmissionRequestV1,
    captured: &NativeSemanticCaptureRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    match current_delivery_gate(tx, operation, original, captured)? {
        SemanticDeliveryGate::Open => Ok(()),
        gate => Err(refused(gate.as_str())),
    }
}

fn current_delivery_gate(
    tx: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    original: &RetainedToolAdmissionRequestV1,
    captured: &NativeSemanticCaptureRecordV1,
) -> Result<SemanticDeliveryGate, AdmissionOperationStoreError> {
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
    if evidence.output_disposition() != disposition {
        return Err(refused("semantic delivery output disposition changed"));
    }
    if evidence.influence().unknown {
        return Ok(SemanticDeliveryGate::UnprovedOrigin);
    }
    let audience = if disposition == SemanticOutputDispositionV1::Withhold {
        let Some(audience) = evidence.withheld_status_audience() else {
            return Ok(SemanticDeliveryGate::StatusAudienceAbsent);
        };
        if !evidence.output_label().flows_to(audience) {
            return Ok(SemanticDeliveryGate::StatusClassificationChanged);
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
    let Some(current) = current else {
        return Ok(SemanticDeliveryGate::SourceAbsent);
    };
    for label in [
        &current.principal_label,
        &current.lineage_label,
        &current.session_label,
    ] {
        if !evidence.output_label().flows_to(label)
            || audience.is_some_and(|audience| !audience.flows_to(label))
        {
            return Ok(SemanticDeliveryGate::BelowVerifiedSource);
        }
    }
    Ok(SemanticDeliveryGate::Open)
}

#[cfg(feature = "admission-test-support")]
impl SqliteAdmissionOperationStore {
    /// Evaluate the current outward-disclosure gates of a terminal original
    /// without publishing anything. Custody and binding failures stay errors,
    /// so a returned gate is always the decision of the delivery boundary.
    pub fn retained_semantic_delivery_gate_for_test(
        &self,
        operation_id: &AdmissionOperationId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<SemanticDeliveryGate, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        schema::verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        schema::authority_validation_time(&tx, now)?;
        let operation = load_operation_for_participant_tx(&tx, operation_id)?
            .ok_or_else(|| refused("retained semantic delivery operation absent"))?;
        let original = retained_request::load_retained_request_tx(&tx, &operation)?
            .ok_or_else(|| refused("retained semantic delivery original absent"))?;
        let binding = original
            .native_security_authority_binding()
            .ok_or_else(|| refused("retained semantic delivery native selection absent"))?;
        let origin = output::authenticated_captured_origin(&tx, &operation, &original, binding)?
            .ok_or_else(|| refused("retained semantic delivery capture absent"))?;
        let gate = current_delivery_gate(&tx, &operation, &original, origin.record())?;
        tx.commit().map_err(sqlite_error)?;
        Ok(gate)
    }
}
