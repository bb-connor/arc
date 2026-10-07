//! Maintenance reads recompute protected contract data without reserving writes.
use super::*;

impl SqliteAdmissionOperationStore {
    /// Return historical constraints, never authority to rerun the captured step.
    /// The reader is freshly authenticated against the current deployment.
    pub fn read_semantic_constraints(
        &self,
        actor: &AuthenticatedRecoveryActor,
        operation: &OperationId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<ResolvedSemanticConstraintsV1, AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::Maintain {
            return Err(refused("semantic constraint read authority"));
        }
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        let now = schema::authority_validation_time(&tx, now)?;
        let profile = protected::deployment_tx(&tx, actor.scope())?;
        super::super::recovery::verify_actor(&tx, actor, &profile, now)?;
        let id = AdmissionOperationId::from_persisted(operation.as_str()).map_err(refused)?;
        let stored = load_by_operation_id_tx(&tx, &id)?
            .ok_or_else(|| refused("semantic constraint operation absent"))?;
        let captured: NativeSemanticCaptureRecordV1 = load(&tx, &capture_key(operation.as_str()))?
            .ok_or_else(|| refused("semantic constraint capture absent"))?;
        let original = retained_request::load_retained_request_tx(&tx, &stored.operation)?
            .ok_or_else(|| refused("semantic constraint original absent"))?;
        original.validate_native_security_authority(&captured.native_authority)?;
        original.validate_native_security_context(&captured.security_context)?;
        let request = original.request_for_revalidation();
        if captured.operation_id != *operation
            || captured.invocation.action.scope != *actor.scope()
            || captured.route.server.as_str() != request.server_id
            || captured.route.tool.as_str() != request.tool_name
            || captured.contract.operation != captured.invocation.action.operation
            || captured.route.operation != captured.invocation.action.operation
            || captured.invocation.action.request_id.as_str() != request.request_id
            || canonical_json_bytes(&captured.invocation).map_err(refused)?
                != canonical_json_bytes(&request.arguments).map_err(refused)?
        {
            return Err(refused("semantic constraint capture binding"));
        }
        super::super::security_participant_state::dispatch_ledger::verify_capture_attachment(
            &tx,
            &stored.operation,
        )?;
        let constraints = resolve_semantic_constraints(
            captured.invocation.action.registry,
            &captured.route,
            &captured.contract,
            &captured.invocation.action.destination,
            &captured.invocation.action.source_label,
            &mut VerificationBudget::new(4096).map_err(refused)?,
        )
        .map_err(refused)?;
        let label = super::super::knowledge::source(
            &tx,
            &profile.native_authority,
            &profile.security_context,
        )?
        .join_restrictions(&constraints.source_label)
        .and_then(|label| label.join_restrictions(&captured.contract.source_label))
        .and_then(|label| label.join_restrictions(&constraints.destination_label))
        .map_err(refused)?;
        let assignment = profile
            .actors
            .as_slice()
            .iter()
            .find(|assignment| {
                assignment.subject == actor.capability().subject
                    && assignment.principal == *actor.principal()
                    && assignment
                        .permissions
                        .as_slice()
                        .contains(&RecoveryPermission::Maintain)
            })
            .ok_or_else(|| refused("semantic constraint reader revoked"))?;
        if !label.flows_to(&assignment.preview_clearance) {
            return Err(refused("semantic constraint audience"));
        }
        if canonical_json_bytes(&constraints).map_err(refused)?.len() > MAX_RECOVERY_WIRE_BYTES {
            return Err(refused("semantic constraint response bound"));
        }
        let later = schema::authority_validation_time(&tx, now)?;
        super::super::recovery::verify_actor(&tx, actor, &profile, later)?;
        tx.commit().map_err(sqlite_error)?;
        Ok(constraints)
    }
}
