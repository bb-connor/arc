use super::*;
use materialization::{step_key, verify_current_prerequisites, verify_materialized_plan};

/// Private, transaction-borrowed semantic evidence cannot be decoded or reused.
pub(in crate::admission_operation_store) struct SemanticCaptureWitness {
    pub(super) record: NativeSemanticCaptureRecordV1,
    pub(super) verified: VerifiedSemanticInvocationV1,
}
impl SemanticCaptureWitness {
    pub(in crate::admission_operation_store) fn valid_until(&self) -> u64 {
        self.verified.valid_until_unix_ms
    }

    /// Classify the status channel before any provider branch is observable.
    /// This is available only after the pure and owning native checks succeeded.
    pub(in crate::admission_operation_store) fn withheld_status_audience(
        &self,
    ) -> Option<&chio_security_types::InformationLabel> {
        if self.record.invocation.action.output != SemanticOutputDispositionV1::Withhold {
            return None;
        }
        self.record
            .contract
            .withheld_status
            .as_ref()
            .map(|status| &status.audience)
    }
}
fn spent_key(
    scope: &RecoveryScopeV1,
    evidence: &EvidenceRef,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "semantic-spent:{}:{}",
        scope_key(scope)?,
        evidence.as_str()
    ))
}
fn current_annotation_answers_required(
    binding: &NativeSecurityAuthorityBindingV1,
) -> Result<bool, AdmissionOperationStoreError> {
    #[cfg(feature = "admission-test-support")]
    {
        Ok(!super::legacy_annotation_capture::selected(
            binding.store_uuid().as_str(),
        )?)
    }
    #[cfg(not(feature = "admission-test-support"))]
    {
        let _ = binding;
        Ok(true)
    }
}

fn current_status_audience_required(
    binding: &NativeSecurityAuthorityBindingV1,
    request: &ToolCallRequest,
) -> Result<bool, AdmissionOperationStoreError> {
    #[cfg(feature = "admission-test-support")]
    {
        Ok(!super::legacy_status_capture::selected(
            binding.store_uuid().as_str(),
            request,
        )?)
    }
    #[cfg(not(feature = "admission-test-support"))]
    {
        let _ = (binding, request);
        Ok(true)
    }
}
/// Only the owning first-input writer constructs this borrowed observation.
/// Every supplied snapshot and original binding is independently checked below.
pub(in crate::admission_operation_store) struct SemanticInputObservation<'a> {
    pub operation: &'a AdmissionOperationV1,
    pub original: &'a chio_kernel::admission_operation::RetainedToolAdmissionRequestV1,
    pub binding: &'a NativeSecurityAuthorityBindingV1,
    pub context: &'a SecurityInvocationContext,
    pub input: &'a chio_kernel::admission_operation::NativeSecurityInputJoinRequestV1,
    pub before: Option<&'a chio_security_types::ports::FlowStateSnapshot>,
    pub resolved: &'a chio_security_types::ports::FlowJoinRequest,
    pub now: u64,
}

/// Verified restriction data for the owning input transaction. It cannot be
/// serialized, cloned, or consumed as a capture owner or disclosure authority.
pub(in crate::admission_operation_store) struct SemanticInputWitness {
    restriction_floor: chio_security_types::InformationLabel,
    withheld_status_audience: Option<chio_security_types::InformationLabel>,
}
impl SemanticInputWitness {
    pub(in crate::admission_operation_store) fn restriction_floor(
        &self,
    ) -> &chio_security_types::InformationLabel {
        &self.restriction_floor
    }

    pub(in crate::admission_operation_store) fn withheld_status_audience(
        &self,
    ) -> Option<&chio_security_types::InformationLabel> {
        self.withheld_status_audience.as_ref()
    }
}

pub(in crate::admission_operation_store) enum SemanticInputAssessment {
    Eligible(SemanticInputWitness),
    Refused(SemanticInputWitness),
}

impl SemanticInputAssessment {
    fn witness(&self) -> &SemanticInputWitness {
        match self {
            Self::Eligible(witness) | Self::Refused(witness) => witness,
        }
    }

    pub(in crate::admission_operation_store) fn restriction_floor(
        &self,
    ) -> &chio_security_types::InformationLabel {
        self.witness().restriction_floor()
    }

    pub(in crate::admission_operation_store) fn withheld_status_audience(
        &self,
    ) -> Option<&chio_security_types::InformationLabel> {
        self.witness().withheld_status_audience()
    }

    pub(in crate::admission_operation_store) fn is_refused(&self) -> bool {
        matches!(self, Self::Refused(_))
    }
}

enum SemanticSourceFacts {
    Input(VerifiedSemanticInputRestrictionsV1),
    Captured(VerifiedSemanticInvocationV1),
}

impl SemanticSourceFacts {
    fn valid_until_unix_ms(&self) -> u64 {
        match self {
            Self::Input(facts) => facts.valid_until_unix_ms(),
            Self::Captured(facts) => facts.valid_until_unix_ms,
        }
    }

    fn endorsement_evidence(&self) -> &[EvidenceRef] {
        match self {
            Self::Input(facts) => facts.endorsement_evidence(),
            Self::Captured(facts) => &facts.endorsement_evidence,
        }
    }

    fn held_evidence(&self) -> &[EvidenceRef] {
        match self {
            Self::Input(facts) => facts.held_evidence(),
            Self::Captured(facts) => &facts.held_evidence,
        }
    }
}

struct SemanticSourceVerification {
    record: NativeSemanticCaptureRecordV1,
    facts: SemanticSourceFacts,
    input_refused: bool,
    input_annotation_floor: Option<chio_security_types::InformationLabel>,
}

enum SourcePhase<'a> {
    CapturedInput,
    BeforeInput {
        before: &'a chio_security_types::ports::FlowStateSnapshot,
        resolved: &'a chio_security_types::ports::FlowJoinRequest,
    },
}

pub(in crate::admission_operation_store) fn verify_input_tx(
    tx: &Transaction<'_>,
    observed: SemanticInputObservation<'_>,
) -> Result<Option<SemanticInputAssessment>, AdmissionOperationStoreError> {
    let request = observed.original.request_for_revalidation();
    if selected_scope(tx, observed.binding, observed.context, request)?.is_none() {
        return Ok(None);
    }
    let before = observed
        .before
        .ok_or_else(|| refused("configured semantic input has no initialized source"))?;
    let retained = retained_request::load_retained_request_tx(tx, observed.operation)?
        .ok_or_else(|| refused("semantic input lacks original custody"))?;
    if retained.canonical_bytes() != observed.original.canonical_bytes()
        || observed.operation.state() != AdmissionOperationState::BrokerAttemptRegistered
        || observed.operation.dispatch_commit().is_some()
    {
        return Err(refused("semantic input original ownership"));
    }
    observed
        .original
        .validate_native_security_authority(observed.binding)?;
    observed
        .original
        .validate_native_security_context(observed.context)?;
    observed
        .input
        .validate(observed.operation.binding().operation_id())?;
    let resolved = crate::security_state::resolve_native_input_join(
        tx,
        observed.binding.security_authority_id().as_str(),
        observed.input,
    )
    .map_err(refused)?;
    if &resolved != observed.resolved || observed.input.key() != &before.key {
        return Err(refused("semantic input resolution changed"));
    }
    let verified = verify_source_tx(
        tx,
        observed.operation,
        request,
        observed.binding,
        observed.context,
        observed.now,
        SourcePhase::BeforeInput {
            before,
            resolved: observed.resolved,
        },
    )?;
    let Some(verified) = verified else {
        return Ok(None);
    };
    let record = &verified.record;
    if !matches!(verified.facts, SemanticSourceFacts::Input(_)) {
        return Err(refused("semantic input verification phase changed"));
    }
    let mut restriction_floor = record.invocation.action.source_label.clone();
    if verified.input_refused {
        if let Some(current) = current_audience(tx, record.invocation.audience.body())? {
            restriction_floor = restriction_floor
                .join_restrictions(&current.body().audience)
                .map_err(refused)?;
        }
    }
    if let Some(current) = &verified.input_annotation_floor {
        restriction_floor = restriction_floor
            .join_restrictions(current)
            .map_err(refused)?;
    }
    let withheld_status_audience =
        if record.invocation.action.output == SemanticOutputDispositionV1::Withhold {
            match record
                .contract
                .withheld_status
                .as_ref()
                .map(|status| &status.audience)
            {
                Some(audience) => Some(audience.clone()),
                None if !current_status_audience_required(observed.binding, request)? => None,
                None => return Err(refused("semantic input status audience absent")),
            }
        } else {
            None
        };
    let witness = SemanticInputWitness {
        restriction_floor,
        withheld_status_audience,
    };
    Ok(Some(if verified.input_refused {
        SemanticInputAssessment::Refused(witness)
    } else {
        SemanticInputAssessment::Eligible(witness)
    }))
}

pub(in crate::admission_operation_store) fn verify_capture_tx(
    tx: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    request: &ToolCallRequest,
    binding: &NativeSecurityAuthorityBindingV1,
    context: &SecurityInvocationContext,
    now: u64,
) -> Result<Option<SemanticCaptureWitness>, AdmissionOperationStoreError> {
    let Some(source) = verify_source_tx(
        tx,
        operation,
        request,
        binding,
        context,
        now,
        SourcePhase::CapturedInput,
    )?
    else {
        return Ok(None);
    };
    let SemanticSourceFacts::Captured(verified) = source.facts else {
        return Err(refused("semantic capture verification phase changed"));
    };
    if source.input_refused {
        return Err(refused("semantic capture has a refused input"));
    }
    Ok(Some(SemanticCaptureWitness {
        record: source.record,
        verified,
    }))
}

fn selected_scope(
    tx: &Transaction<'_>,
    binding: &NativeSecurityAuthorityBindingV1,
    context: &SecurityInvocationContext,
    request: &ToolCallRequest,
) -> Result<Option<RecoveryScopeV1>, AdmissionOperationStoreError> {
    let selected: Option<RecoveryScopeV1> = load(
        tx,
        &route_key(binding, context, &request.server_id, &request.tool_name)?,
    )?;
    if selected.is_none()
        && request
            .arguments
            .get("schema")
            .and_then(serde_json::Value::as_str)
            == Some("chio.semantic.invocation.v1")
    {
        return Err(refused("unconfigured semantic route"));
    }
    Ok(selected)
}

fn verify_source_tx(
    tx: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    request: &ToolCallRequest,
    binding: &NativeSecurityAuthorityBindingV1,
    context: &SecurityInvocationContext,
    now: u64,
    phase: SourcePhase<'_>,
) -> Result<Option<SemanticSourceVerification>, AdmissionOperationStoreError> {
    let selected = selected_scope(tx, binding, context, request)?;
    let Some(scope) = selected else {
        return Ok(None);
    };
    if stopped(tx, &scope)? {
        return Err(refused("semantic emergency stop"));
    }
    let installed = installation(tx, &scope)?;
    if installed.native_authority != *binding
        || recovery_flow_key(&installed.security_context) != recovery_flow_key(context)
        || installed.security_context.as_v1().context_generation()
            != context.as_v1().context_generation()
    {
        return Err(refused("native mapping"));
    }
    let registry = installed.compile()?;
    let mut budget = VerificationBudget::new(4096).map_err(refused)?;
    let invocation: SemanticInvocationV1 =
        decode_contract(&canonical_json_bytes(&request.arguments).map_err(refused)?)
            .map_err(refused)?;
    let (route, contract) = registry
        .resolve(&request.server_id, &request.tool_name)
        .map_err(refused)?;
    let (state, _) = crate::security_state::observe_native_flow_state(
        tx,
        binding.security_authority_id().as_str(),
        &recovery_flow_key(context),
    )
    .map_err(refused)?;
    let state = state.ok_or_else(|| refused("native source absent"))?;
    let framed = &invocation.action.native_source;
    if framed.key != semantic_content_digest(&state.key).map_err(refused)? {
        return Err(refused("native source key"));
    }
    let mut original = state.clone();
    original.context_generation = framed.generation.get();
    original.principal_label = framed.principal_label.clone();
    original.lineage_label = framed.lineage_label.clone();
    original.session_label = framed.session_label.clone();
    let source_proven = match &phase {
        SourcePhase::CapturedInput => {
            super::super::security_participant_state::prove_semantic_source_history(
                tx,
                binding,
                operation.binding().operation_id(),
                &original,
                &state,
            )?
        }
        SourcePhase::BeforeInput { before, .. } => {
            if **before != state {
                return Err(refused("semantic input snapshot changed"));
            }
            super::super::security_participant_state::prove_semantic_before_input_source_history(
                tx,
                binding,
                operation.binding().operation_id(),
                &original,
                &state,
            )?
        }
    };
    if !source_proven {
        return Err(refused("foreign source generation"));
    }
    let mut source = state
        .principal_label
        .join_restrictions(&state.lineage_label)
        .and_then(|source| source.join_restrictions(&state.session_label))
        .map_err(refused)?;
    if let SourcePhase::BeforeInput { resolved, .. } = &phase {
        source = source
            .join_restrictions(&resolved.principal_join)
            .and_then(|label| label.join_restrictions(&resolved.lineage_join))
            .and_then(|label| label.join_restrictions(&resolved.session_join))
            .map_err(refused)?;
    }
    let (influence, externally_influenced) = materialization::materialized_influence(
        tx,
        &invocation,
        binding,
        context,
        contract.external_influence,
        request.model_metadata.as_ref(),
        &mut budget,
    )?;
    let namespace: [u8; 32] = hex::decode(operation.binding().request_namespace_digest().as_str())
        .map_err(refused)?
        .try_into()
        .map_err(|_| refused("namespace"))?;
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
        externally_influenced,
        influence,
        native_disclosure_target: request
            .declassification_grant
            .as_ref()
            .map(|grant| grant.body().target_label()),
        now_unix_ms: now,
    };
    let annotations_required = current_annotation_answers_required(binding)?;
    let status_audience_required = current_status_audience_required(binding, request)?;
    let before_input = matches!(&phase, SourcePhase::BeforeInput { .. });
    #[cfg(feature = "admission-test-support")]
    let verified = {
        if !annotations_required && !status_audience_required {
            return Err(refused("legacy capture models cannot be combined"));
        }
        if before_input {
            let input = if !status_audience_required {
                verify_modeled_legacy_input_restrictions(
                    &registry,
                    &invocation,
                    &expectation,
                    &mut budget,
                    ModeledSemanticInputProfileV1::MissingStatus,
                )
            } else if !annotations_required {
                verify_modeled_legacy_input_restrictions(
                    &registry,
                    &invocation,
                    &expectation,
                    &mut budget,
                    ModeledSemanticInputProfileV1::IncompleteAnnotations,
                )
            } else {
                verify_semantic_input_restrictions(
                    &registry,
                    &invocation,
                    &expectation,
                    &mut budget,
                )
            };
            input.map(SemanticSourceFacts::Input)
        } else {
            let captured = if !status_audience_required {
                verify_modeled_legacy_missing_withheld_status(
                    &registry,
                    &invocation,
                    &expectation,
                    &mut budget,
                )
            } else if !annotations_required {
                verify_modeled_legacy_incomplete_annotations(
                    &registry,
                    &invocation,
                    &expectation,
                    &mut budget,
                )
            } else {
                verify_semantic_invocation(&registry, &invocation, &expectation, &mut budget)
            };
            captured.map(SemanticSourceFacts::Captured)
        }
    };
    #[cfg(not(feature = "admission-test-support"))]
    let verified = {
        let _ = status_audience_required;
        if before_input {
            verify_semantic_input_restrictions(&registry, &invocation, &expectation, &mut budget)
                .map(SemanticSourceFacts::Input)
        } else {
            verify_semantic_invocation(&registry, &invocation, &expectation, &mut budget)
                .map(SemanticSourceFacts::Captured)
        }
    };
    let verified = verified.map_err(refused)?;
    let acl = invocation.audience.body();
    let current = current_audience(tx, acl)?;
    let mut input_refused = current.as_ref() != Some(&invocation.audience);
    if input_refused
        && (!before_input
            || invocation.action.output != SemanticOutputDispositionV1::Withhold
            || contract.withheld_status.is_none())
    {
        return Err(refused("current ACL absent or changed"));
    }
    verify_materialized_plan(tx, &invocation, &mut budget)?;
    verify_current_prerequisites(tx, &invocation, now, &mut budget)?;
    let input_annotation_floor = if annotations_required {
        if before_input
            && invocation.action.output == SemanticOutputDispositionV1::Withhold
            && contract.withheld_status.is_some()
        {
            let current =
                annotations::assess_current_annotations(tx, &invocation, route, now, &mut budget)?;
            input_refused |= current.basis_changed;
            current.basis_changed.then_some(current.restriction_floor)
        } else {
            annotations::verify_current_annotations(tx, &invocation, route, now, &mut budget)?;
            None
        }
    } else {
        None
    };
    if load::<NativeSemanticCaptureRecordV1>(
        tx,
        &step_key(&scope, &invocation.action.plan, &invocation.action.step)?,
    )?
    .is_some()
    {
        return Err(refused("plan step already captured"));
    }
    for evidence in verified
        .endorsement_evidence()
        .iter()
        .chain(verified.held_evidence())
    {
        if load::<OperationId>(tx, &spent_key(&scope, evidence)?)?.is_some() {
            return Err(refused("semantic evidence already consumed"));
        }
    }
    Ok(Some(SemanticSourceVerification {
        record: NativeSemanticCaptureRecordV1 {
            operation_id: OperationId::new(operation.binding().operation_id().as_str())
                .map_err(refused)?,
            invocation,
            contract: contract.clone(),
            route: route.clone(),
            native_authority: binding.clone(),
            security_context: context.clone(),
            captured_at_unix_ms: SafeInteger::new(now).map_err(refused)?,
            valid_until_unix_ms: SafeInteger::new(verified.valid_until_unix_ms())
                .map_err(refused)?,
        },
        facts: verified,
        input_refused,
        input_annotation_floor,
    }))
}
pub(in crate::admission_operation_store) fn capture_tx(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    witness: &SemanticCaptureWitness,
    operation: &AdmissionOperationV1,
) -> Result<(), AdmissionOperationStoreError> {
    let record = &witness.record;
    let scope = &record.invocation.action.scope;
    if record.operation_id.as_str() != operation.binding().operation_id().as_str()
        || operation.state() != AdmissionOperationState::DispatchCommitted
    {
        return Err(refused("capture successor"));
    }
    for evidence in witness
        .verified
        .endorsement_evidence
        .iter()
        .chain(&witness.verified.held_evidence)
    {
        save(
            tx,
            owner,
            scope,
            &spent_key(scope, evidence)?,
            "command",
            &record.operation_id,
        )?;
    }
    for prerequisite in record.invocation.prerequisites.as_slice() {
        if let Some(lease) = &prerequisite.body().lease {
            save(
                tx,
                owner,
                scope,
                &format!(
                    "semantic-lease-spent:{}:{}",
                    scope_key(scope)?,
                    lease.as_str()
                ),
                "command",
                &record.operation_id,
            )?;
        }
    }
    save(
        tx,
        owner,
        scope,
        &capture_key(record.operation_id.as_str()),
        "command",
        record,
    )?;
    save(
        tx,
        owner,
        scope,
        &step_key(
            scope,
            &record.invocation.action.plan,
            &record.invocation.action.step,
        )?,
        "command",
        record,
    )
}

impl SqliteAdmissionOperationStore {
    pub(in crate::admission_operation_store) fn captured_semantic_output_disposition(
        &self,
        operation: &AdmissionOperationV1,
        request: &ToolCallRequest,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Option<SemanticOutputDispositionV1>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        schema::verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        schema::authority_validation_time(&tx, now)?;
        let captured: Option<NativeSemanticCaptureRecordV1> = load(
            &tx,
            &capture_key(operation.binding().operation_id().as_str()),
        )?;
        let Some(captured) = captured else {
            if request
                .arguments
                .get("schema")
                .and_then(serde_json::Value::as_str)
                == Some("chio.semantic.invocation.v1")
            {
                return Err(refused("missing semantic output custody"));
            }
            return Ok(None);
        };
        let original = retained_request::load_retained_request_tx(&tx, operation)?
            .ok_or_else(|| refused("missing retained output request"))?;
        if original.request_for_revalidation().arguments != request.arguments
            || serde_json::to_value(&captured.invocation).map_err(refused)? != request.arguments
            || canonical_json_bytes(&original.request_for_revalidation().capability)
                .map_err(refused)?
                != canonical_json_bytes(&request.capability).map_err(refused)?
            || captured.operation_id.as_str() != operation.binding().operation_id().as_str()
            || !matches!(
                operation.state(),
                AdmissionOperationState::Finalizing
                    | AdmissionOperationState::Completed
                    | AdmissionOperationState::DeniedAfterDelivery
            )
        {
            return Err(refused("output custody changed"));
        }
        super::super::security_participant_state::dispatch_ledger::verify_capture_attachment(
            &tx, operation,
        )?;
        let disposition = captured.invocation.action.output;
        // Finalizing projects retained facts internally. Current delivery is a
        // separate gate after terminal commitment, including historical calls.
        if matches!(
            operation.state(),
            AdmissionOperationState::Completed | AdmissionOperationState::DeniedAfterDelivery
        ) {
            if disposition == SemanticOutputDispositionV1::ReturnValue
                && stopped(&tx, &captured.invocation.action.scope)?
            {
                return Err(refused("output emergency stop"));
            }
            delivery::require_current_delivery(&tx, operation, &original, &captured)?;
        }
        tx.commit().map_err(sqlite_error)?;
        Ok(Some(disposition))
    }

    /// Last local dispatch check. The original capture remains spent on refusal.
    /// Only a connection with an actual native dispatch identity may submit.
    pub fn semantic_dispatch_capture(
        &self,
        operation: &str,
        request_id: &str,
        signed_capability_hash: &str,
    ) -> Result<NativeSemanticCaptureRecordV1, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, None)?;
        let id = AdmissionOperationId::from_persisted(operation).map_err(refused)?;
        let stored =
            load_by_operation_id_tx(&tx, &id)?.ok_or_else(|| refused("operation absent"))?;
        if !matches!(
            stored.operation.state(),
            AdmissionOperationState::DispatchCommitted
        ) {
            return Err(refused("dispatch state"));
        }
        let record: NativeSemanticCaptureRecordV1 = load(&tx, &capture_key(operation))?
            .ok_or_else(|| refused("semantic capture absent"))?;
        let original = retained_request::load_retained_request_tx(&tx, &stored.operation)?
            .ok_or_else(|| refused("original request absent"))?;
        if record.invocation.action.request_id.as_str() != request_id
            || original.request_for_revalidation().request_id != request_id
            || sha256_hex(
                &canonical_json_bytes(&original.request_for_revalidation().capability)
                    .map_err(refused)?,
            ) != signed_capability_hash
        {
            return Err(refused("dispatch caller"));
        }
        let now = schema::observe_authority_time(&tx)?;
        let installed = installation(&tx, &record.invocation.action.scope)?;
        if stopped(&tx, &record.invocation.action.scope)?
            || installed.compile()?.digest() != record.invocation.action.registry
            || now >= record.valid_until_unix_ms.get()
        {
            return Err(refused("dispatch basis stale"));
        }
        let capability = &original.request_for_revalidation().capability;
        if now / 1000 >= capability.expires_at {
            return Err(refused("dispatch capability expired"));
        }
        for id in std::iter::once(capability.id.as_str()).chain(
            capability
                .delegation_chain
                .iter()
                .map(|link| link.capability_id.as_str()),
        ) {
            let revoked: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM revoked_capabilities WHERE capability_id=?1)",
                    [id],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
            if revoked {
                return Err(refused("dispatch capability revoked"));
            }
        }
        super::super::security_participant_state::dispatch_ledger::verify_semantic_dispatch_policy(
            &tx,
            &stored.operation,
            now,
        )?;
        materialization::verify_dispatch_prerequisites(&tx, &record, now)?;
        if current_annotation_answers_required(&record.native_authority)? {
            annotations::verify_current_annotations(
                &tx,
                &record.invocation,
                &record.route,
                now,
                &mut VerificationBudget::new(4096).map_err(refused)?,
            )?;
        }
        let acl = record.invocation.audience.body();
        let current = current_audience(&tx, acl)?.ok_or_else(|| refused("ACL absent"))?;
        if current != record.invocation.audience || now >= acl.valid_until_unix_ms.get() {
            return Err(refused("dispatch ACL stale"));
        }
        let submitted = format!("semantic-submission:{operation}");
        if load::<OperationId>(&tx, &submitted)?.is_some() {
            return Err(refused("native submission already consumed"));
        }
        save(
            &tx,
            &self.serving_owner,
            &record.invocation.action.scope,
            &submitted,
            "command",
            &record.operation_id,
        )?;
        let final_now = schema::observe_authority_time(&tx)?;
        if final_now >= record.valid_until_unix_ms.get()
            || final_now / 1000 >= capability.expires_at
        {
            return Err(refused("submission authority expired before commit"));
        }
        super::super::security_participant_state::dispatch_ledger::verify_semantic_dispatch_policy(
            &tx,
            &stored.operation,
            final_now,
        )?;
        self.commit_write(tx)?;
        self.sync_after_write(&connection)?;
        Ok(record)
    }
}
