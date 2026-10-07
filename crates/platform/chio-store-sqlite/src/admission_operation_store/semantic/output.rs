//! Output origin comes from the authenticated original capture, never a caller label.
use super::*;
use chio_kernel::admission_operation::RetainedToolAdmissionRequestV1;
use chio_security_types::{knowledge::ArtifactInfluenceV1, InformationLabel};

/// Transaction-derived data for the native output writer. This is neither an
/// authorization token nor a replacement for the writer's original recovery lease.
pub(in crate::admission_operation_store) struct SemanticOutputInfluence {
    label: InformationLabel,
    influence: ArtifactInfluenceV1,
    disposition: SemanticOutputDispositionV1,
    withheld_status_audience: Option<InformationLabel>,
}

impl SemanticOutputInfluence {
    pub(in crate::admission_operation_store) fn output_label(&self) -> &InformationLabel {
        &self.label
    }

    pub(in crate::admission_operation_store) fn influence(&self) -> &ArtifactInfluenceV1 {
        &self.influence
    }

    pub(in crate::admission_operation_store) fn output_disposition(
        &self,
    ) -> SemanticOutputDispositionV1 {
        self.disposition
    }

    pub(in crate::admission_operation_store) fn withheld_status_audience(
        &self,
    ) -> Option<&InformationLabel> {
        self.withheld_status_audience.as_ref()
    }
}

pub(in crate::admission_operation_store) fn authenticated_native_output_influence(
    tx: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    original_request: &RetainedToolAdmissionRequestV1,
    native_binding: &NativeSecurityAuthorityBindingV1,
) -> Result<Option<SemanticOutputInfluence>, AdmissionOperationStoreError> {
    let Some(origin) =
        authenticated_captured_origin(tx, operation, original_request, native_binding)?
    else {
        return Ok(None);
    };
    let captured = origin.record();
    if !matches!(
        operation.state(),
        AdmissionOperationState::Finalizing
            | AdmissionOperationState::Completed
            | AdmissionOperationState::DeniedAfterDelivery
    ) {
        return Err(refused("semantic output capture binding changed"));
    }
    let classification = classify_captured_origin(&origin)?;
    let action = &captured.invocation.action;
    let commitment_body = chio_core::CanonicalBytes::new(&(
        &captured.operation_id,
        operation.native_dispatch_ledger_digest(),
        semantic_action_digest(action).map_err(refused)?,
        &action.inputs,
        &classification.label,
    ))
    .map_err(refused)?;
    let influence = ArtifactInfluenceV1 {
        commitment: CanonicalPayloadDigest::from_bytes(
            *RecoveryDigestDomain::SemanticNativeOutputOrigin
                .digest(&commitment_body)
                .as_bytes(),
        ),
        externally_influenced: classification.externally_influenced,
        unknown: classification.unknown,
    };
    Ok(Some(SemanticOutputInfluence {
        label: classification.label,
        influence,
        disposition: action.output,
        withheld_status_audience: classification.withheld_status_audience,
    }))
}

/// Private retained capture custody, constructed only after the owning native
/// operation, original request and dispatch attachment agree. It is data and
/// cannot itself select output, status or execution permission.
pub(super) struct AuthenticatedCapturedOrigin {
    captured: NativeSemanticCaptureRecordV1,
}

impl AuthenticatedCapturedOrigin {
    pub(super) fn record(&self) -> &NativeSemanticCaptureRecordV1 {
        &self.captured
    }
}

pub(super) fn authenticated_captured_origin(
    tx: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    original_request: &RetainedToolAdmissionRequestV1,
    native_binding: &NativeSecurityAuthorityBindingV1,
) -> Result<Option<AuthenticatedCapturedOrigin>, AdmissionOperationStoreError> {
    let captured: Option<NativeSemanticCaptureRecordV1> = load(
        tx,
        &capture_key(operation.binding().operation_id().as_str()),
    )?;
    let original = retained_request::load_retained_request_tx(tx, operation)?
        .ok_or_else(|| refused("semantic output lacks original custody"))?;
    if original.canonical_bytes() != original_request.canonical_bytes() {
        return Err(refused("semantic output original changed"));
    }
    let request = original.request_for_revalidation();
    let Some(captured) = captured else {
        if request
            .arguments
            .get("schema")
            .and_then(serde_json::Value::as_str)
            == Some("chio.semantic.invocation.v1")
        {
            return Err(refused("semantic output lost capture"));
        }
        return Ok(None);
    };
    original.validate_native_security_authority(native_binding)?;
    original.validate_native_security_context(&captured.security_context)?;
    if captured.operation_id.as_str() != operation.binding().operation_id().as_str()
        || captured.native_authority != *native_binding
        || captured.route.server.as_str() != request.server_id
        || captured.route.tool.as_str() != request.tool_name
        || captured.route.operation != captured.invocation.action.operation
        || captured.contract.operation != captured.invocation.action.operation
        || captured.invocation.action.request_id.as_str() != request.request_id
        || canonical_json_bytes(&captured.invocation).map_err(refused)?
            != canonical_json_bytes(&request.arguments).map_err(refused)?
    {
        return Err(refused("semantic output capture binding changed"));
    }
    super::super::security_participant_state::dispatch_ledger::verify_capture_attachment(
        tx, operation,
    )?;

    Ok(Some(AuthenticatedCapturedOrigin { captured }))
}

/// Classification requires the private authenticated retained-capture witness.
/// It returns data and cannot select output or status authority.
pub(super) struct CapturedOriginClassification {
    pub(super) label: InformationLabel,
    pub(super) externally_influenced: bool,
    pub(super) unknown: bool,
    pub(super) withheld_status_audience: Option<InformationLabel>,
}

pub(super) fn classify_captured_origin(
    origin: &AuthenticatedCapturedOrigin,
) -> Result<CapturedOriginClassification, AdmissionOperationStoreError> {
    let captured = origin.record();
    let action = &captured.invocation.action;
    let mut label = action
        .source_label
        .join_restrictions(&captured.contract.source_label)
        .map_err(refused)?;
    if captured.contract.kind == SemanticOperationKindV1::SupportRead {
        let destination = captured
            .route
            .destinations
            .as_slice()
            .iter()
            .find(|destination| destination.destination == action.destination)
            .ok_or_else(|| refused("semantic output destination absent"))?;
        let acl = captured.invocation.audience.body();
        if acl.scope != action.scope
            || acl.provider != destination.provider
            || acl.account != destination.account
            || acl.resource != destination.resource
            || acl.subject_mapping != destination.subject_mapping
            || acl.query != destination.acl_query
        {
            return Err(refused("semantic output audience binding changed"));
        }
        label = label
            .join_restrictions(&destination.audience)
            .and_then(|label| label.join_restrictions(&acl.audience))
            .map_err(refused)?;
    }
    let withheld_status_audience = captured
        .contract
        .withheld_status
        .as_ref()
        .map(|status| status.audience.clone());
    if action.output == SemanticOutputDispositionV1::Withhold {
        if let Some(status) = &withheld_status_audience {
            label = label.join_restrictions(status).map_err(refused)?;
        }
    }
    let annotation_answers = captured
        .invocation
        .annotations
        .as_slice()
        .iter()
        .map(|annotation| {
            Ok((
                semantic_key_digest(annotation.authority_key()).map_err(refused)?,
                &annotation.body().input,
            ))
        })
        .collect::<Result<Vec<_>, AdmissionOperationStoreError>>()?;
    let annotations_complete = captured
        .route
        .annotators
        .as_slice()
        .iter()
        .all(|authority| {
            action.inputs.as_slice().iter().all(|input| {
                annotation_answers
                    .iter()
                    .any(|(key, answered)| *key == authority.key && *answered == input)
            })
        });
    let status_complete = action.output != SemanticOutputDispositionV1::Withhold
        || withheld_status_audience.is_some();
    let unknown = !annotations_complete || !status_complete;
    if unknown {
        // An accepted historical effect retains its physical finality. An
        // incomplete source proof cannot authorize finite output disclosure.
        label = InformationLabel::Top;
    }
    Ok(CapturedOriginClassification {
        label,
        externally_influenced: action.externally_influenced || captured.contract.external_influence,
        unknown,
        withheld_status_audience,
    })
}

#[cfg(feature = "admission-test-support")]
impl SqliteAdmissionOperationStore {
    /// Read only authenticated retained output classification for upgrade
    /// fixtures. This returns data and cannot authorize a capture or effect.
    pub fn retained_semantic_output_influence_for_test(
        &self,
        operation_id: &AdmissionOperationId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Option<(InformationLabel, ArtifactInfluenceV1)>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        schema::verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        schema::authority_validation_time(&tx, now)?;
        let operation = load_operation_for_participant_tx(&tx, operation_id)?
            .ok_or_else(|| refused("retained semantic output operation absent"))?;
        let original = retained_request::load_retained_request_tx(&tx, &operation)?
            .ok_or_else(|| refused("retained semantic output original absent"))?;
        let binding = original
            .native_security_authority_binding()
            .ok_or_else(|| refused("retained semantic output native selection absent"))?;
        let evidence = authenticated_native_output_influence(&tx, &operation, &original, binding)?;
        let classification = evidence.map(|evidence| {
            (
                evidence.output_label().clone(),
                evidence.influence().clone(),
            )
        });
        tx.commit().map_err(sqlite_error)?;
        Ok(classification)
    }
}
