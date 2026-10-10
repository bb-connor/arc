//! Cold validation returns classification data, never a fresh producer witness.
use super::*;

/// The native history owner independently authenticates each journal field and
/// the prior influence at the original cut. Decoded origin fields are not a
/// substitute for these native observations or the authenticated global prefix.
pub(in crate::admission_operation_store) struct HistoricalSemanticRefusedInputObservation<'a> {
    pub operation: &'a AdmissionOperationV1,
    pub original: &'a RetainedToolAdmissionRequestV1,
    pub native_authority: &'a NativeSecurityAuthorityBindingV1,
    pub input: &'a NativeSecurityInputJoinRequestV1,
    pub before: &'a FlowStateSnapshot,
    pub joined: &'a FlowJoinRequest,
    pub snapshot: &'a FlowStateSnapshot,
    pub input_global_commit: u64,
    pub observed_at_unix_ms: u64,
    pub prior_influence: Option<&'a ArtifactInfluenceV1>,
}

/// No Deserialize or conversion to the fresh Input producer is available.
pub(in crate::admission_operation_store) struct SemanticHistoricalInputOriginData {
    label: InformationLabel,
    influence: ArtifactInfluenceV1,
}

impl SemanticHistoricalInputOriginData {
    pub(in crate::admission_operation_store) fn source_label(&self) -> &InformationLabel {
        &self.label
    }

    pub(in crate::admission_operation_store) fn influence(&self) -> &ArtifactInfluenceV1 {
        &self.influence
    }
}

pub(in crate::admission_operation_store) fn validate_historical_semantic_refused_input_origin(
    tx: &Connection,
    canonical_origin: &[u8],
    observed: HistoricalSemanticRefusedInputObservation<'_>,
) -> Result<SemanticHistoricalInputOriginData, AdmissionOperationStoreError> {
    if canonical_origin.is_empty() || canonical_origin.len() > MAX_ORIGIN_BYTES {
        return Err(refused(
            "historical semantic Input origin envelope exhausted",
        ));
    }
    let body: RefusedInputOriginBody = serde_json::from_slice(canonical_origin).map_err(refused)?;
    let canonical = CanonicalBytes::new(&body).map_err(refused)?;
    if canonical.as_bytes() != canonical_origin {
        return Err(refused("historical semantic Input origin is not canonical"));
    }
    let cut = body.selected_source_cut.get();
    let input_cut = observed
        .input_global_commit
        .checked_sub(1)
        .ok_or_else(|| refused("historical semantic Input global source absent"))?;
    let request = observed.original.request_for_revalidation();
    observed.input.validate(observed.input.operation_id())?;
    observed
        .original
        .validate_native_security_authority(observed.native_authority)?;
    observed
        .original
        .validate_native_security_context(&body.security_context)?;
    observed
        .original
        .validate_binding(observed.operation.binding())?;
    if cut == 0
        || cut >= observed.input_global_commit
        || body.operation != *observed.input.operation_id()
        || body.operation != *observed.operation.binding().operation_id()
        || body.native_authority != *observed.native_authority
        || body.input != *observed.input
        || body.before != *observed.before
        || body.prior_influence.as_ref() != observed.prior_influence
        || recovery_flow_key(&body.security_context) != *observed.input.key()
        || canonical_json_bytes(&body.original_request).map_err(refused)?
            != observed.original.canonical_bytes()
        || canonical_json_bytes(&body.invocation).map_err(refused)?
            != canonical_json_bytes(&request.arguments).map_err(refused)?
        || body.observed_at_unix_ms.get() > observed.observed_at_unix_ms
        || observed
            .observed_at_unix_ms
            .abs_diff(body.observed_at_unix_ms.get())
            > MAX_TRUSTED_CLOCK_SKEW_MS
    {
        return Err(refused("historical semantic Input original source changed"));
    }
    validate_native_resolution(&body)?;
    let scope = &body.invocation.action.scope;
    body.installation.validate_at_cut(
        tx,
        &format!("semantic-deployment:{}", scope_key(scope)?),
        scope,
        "deployment",
        input_cut,
    )?;
    body.route_selection.validate_at_cut(
        tx,
        &route_key(
            observed.native_authority,
            &body.security_context,
            &request.server_id,
            &request.tool_name,
        )?,
        scope,
        "deployment",
        input_cut,
    )?;
    let installation = &body.installation.body;
    if body.route_selection.body != *scope
        || installation.native_authority != *observed.native_authority
        || recovery_flow_key(&installation.security_context)
            != recovery_flow_key(&body.security_context)
        || installation.security_context.as_v1().context_generation()
            != body.security_context.as_v1().context_generation()
    {
        return Err(refused(
            "historical semantic Input installation mapping changed",
        ));
    }
    let registry = installation.compile()?;
    let (route, contract) = registry
        .resolve(&request.server_id, &request.tool_name)
        .map_err(refused)?;
    if *route != body.route || *contract != body.contract {
        return Err(refused("historical semantic Input exact contract changed"));
    }
    body.framing
        .validate_at_cut(tx, &body.invocation, input_cut)?;
    body.audience
        .validate_at_cut(tx, body.invocation.audience.body(), input_cut)?;
    for source in body.annotations.as_slice() {
        let signer = semantic_key_digest(source.body.authority_key()).map_err(refused)?;
        source.validate_at_cut(
            tx,
            &annotations::annotation_key(scope, signer, &source.body.body().input)?,
            scope,
            "command",
            input_cut,
        )?;
    }
    let (influence, lower_external, _) = body.framing.influence_basis(
        &body.invocation,
        request,
        contract.external_influence,
        observed.prior_influence,
    )?;
    if lower_external && !body.invocation.action.externally_influenced {
        return Err(refused(
            "historical semantic Input erased inherited influence",
        ));
    }
    let source = body
        .before
        .principal_label
        .join_restrictions(&body.before.lineage_label)
        .and_then(|label| label.join_restrictions(&body.before.session_label))
        .and_then(|label| label.join_restrictions(&body.resolved.principal_join))
        .and_then(|label| label.join_restrictions(&body.resolved.lineage_join))
        .and_then(|label| label.join_restrictions(&body.resolved.session_join))
        .map_err(refused)?;
    let action = &body.invocation.action;
    let namespace: [u8; 32] = hex::decode(
        observed
            .operation
            .binding()
            .request_namespace_digest()
            .as_str(),
    )
    .map_err(refused)?
    .try_into()
    .map_err(|_| refused("historical semantic Input namespace changed"))?;
    let expectation = SemanticInvocationExpectationV1 {
        server: &request.server_id,
        tool: &request.tool_name,
        request_id: &request.request_id,
        request_namespace: RequestNamespaceDigest::from_bytes(namespace),
        capability: CapabilityBodyDigest::from_bytes(
            *semantic_content_digest(&request.capability.signing_body())
                .map_err(refused)?
                .as_bytes(),
        ),
        request_semantics: chio_kernel::recovery::semantic_request_semantics(request)
            .map_err(refused)?,
        source_label: &source,
        // Extra historical influence remains conservative. The independent
        // framing digest and authenticated source flags prohibit clean forgery.
        externally_influenced: action.externally_influenced,
        influence,
        native_disclosure_target: request
            .declassification_grant
            .as_ref()
            .map(|grant| grant.body().target_label()),
        now_unix_ms: body.observed_at_unix_ms.get(),
    };
    verify_semantic_input_restrictions(
        &registry,
        &body.invocation,
        &expectation,
        &mut VerificationBudget::new(4096).map_err(refused)?,
    )
    .map_err(refused)?;
    let classification = classify_body(&body, request)?;
    if !classification.refused
        || classification.label != body.source_label
        || classification.external != body.externally_influenced
        || classification.unknown != body.unknown
    {
        return Err(refused("historical semantic Input classification changed"));
    }
    validate_joined_body(&body, observed.joined, observed.snapshot)?;
    Ok(SemanticHistoricalInputOriginData {
        label: body.source_label.clone(),
        influence: origin_influence(&canonical, &body),
    })
}

fn validate_native_resolution(
    body: &RefusedInputOriginBody,
) -> Result<(), AdmissionOperationStoreError> {
    let mut source = body.input.input_label().clone();
    for label in [
        &body.before.principal_label,
        &body.before.lineage_label,
        &body.before.session_label,
    ] {
        source = source.join_restrictions(label).map_err(refused)?;
    }
    let expected = FlowJoinRequest {
        key: body.input.key().clone(),
        principal_join: source.clone(),
        lineage_join: source.clone(),
        session_join: source,
        transition_id: body.input.transition_id().clone(),
    };
    if expected != body.resolved || body.before.key != *body.input.key() {
        return Err(refused(
            "historical semantic Input pre-floor resolution changed",
        ));
    }
    Ok(())
}
