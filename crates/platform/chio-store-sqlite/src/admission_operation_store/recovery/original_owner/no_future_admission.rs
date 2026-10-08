//! Native absence or compensation is proved under the actual owning writer.
use super::*;
use chio_kernel::admission_operation::RetainedToolAdmissionRequestV1;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) enum ContinuationClosure {
    Unmaterialized,
    Compensated {
        operation: OperationRef,
        retained_request_digest: CanonicalPayloadDigest,
        reservation_digest: CanonicalPayloadDigest,
    },
}

/// This role borrows the actual transaction, owner and prepared authority cut.
/// Its fields cannot be reconstructed from an effect label or a wire record.
pub(in crate::admission_operation_store) struct AuthenticatedNoFutureNativeAdmission<
    'owner,
    'tx,
    'conn,
> {
    tx: &'tx Transaction<'conn>,
    owner: &'owner SqliteServingOwner,
    cut: NativeSourceTransactionOrigin<'owner>,
    record: Box<RecoveryWorkflowRecordV1>,
    workflow: SourceVersion,
    quota: SourceVersion,
    continuation: ContinuationClosure,
    now: u64,
}

pub(super) fn eligible(record: &RecoveryWorkflowRecordV1) -> bool {
    record.admission_closed
        && !record.captured
        && record.historical_hold.is_none()
        && ((record.control == WorkflowControlV1::Cancelled
            && record.effect == EffectObservationV1::NeverAdmitted)
            || (matches!(
                record.control,
                WorkflowControlV1::Active
                    | WorkflowControlV1::CancelRequested
                    | WorkflowControlV1::Cancelled
            ) && matches!(
                record.effect,
                EffectObservationV1::ClosedBeforeEffect { .. }
            )))
}

fn no_output(record: &RecoveryWorkflowRecordV1) -> Result<(), AdmissionOperationStoreError> {
    if record.captured
        || record.captured_deployment.is_some()
        || record.historical_hold.is_some()
        || record.provider_finality.is_some()
        || record.provider_lookups.get() != 0
        || record.release != ReleaseDispositionV1::NotAvailable
    {
        return Err(invariant(
            "original owner retains a captured or output obligation",
        ));
    }
    Ok(())
}

fn reservation(
    record: &RecoveryWorkflowRecordV1,
) -> Result<CanonicalPayloadDigest, AdmissionOperationStoreError> {
    let action = record
        .action
        .as_ref()
        .ok_or_else(|| invariant("materialized closure lacks its action"))?;
    let bytes = record
        .process_reservation
        .as_ref()
        .ok_or_else(|| invariant("materialized closure lacks its acknowledged reservation"))?
        .as_str()
        .as_bytes();
    let retained: RecoveryProcessReservationV1 = decode(bytes)?;
    if action.scope != record.scope
        || action.workflow_id != record.workflow_id
        || action.step_id != record.step_id
        || action.continuation_id != record.continuation_id
        || action.origin != record.origin
        || record.seed.request_id != action.request_id.as_str()
        || retained.process_id != record.scope.process_id.as_str()
        || retained.continuation_id != record.continuation_id
        || retained.operation_key != format!("recovery:{}", record.continuation_id.as_str())
        || retained.request_id != action.request_id.as_str()
        || retained.capability_digest != sha256_hex(&encode(&record.seed.capability)?)
        || retained.unsigned_intent
            != IntentDigest::from_bytes(hash(RecoveryDigestDomain::ActionIntent, action)?)
        || retained.runtime_id.is_empty()
        || retained.server_id.is_empty()
        || retained.host_binding.is_empty()
    {
        return Err(invariant(
            "original closure changed its acknowledged process reservation",
        ));
    }
    Ok(CanonicalPayloadDigest::from_bytes(
        *chio_core::sha256(bytes).as_bytes(),
    ))
}

fn continuation_closure(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
) -> Result<ContinuationClosure, AdmissionOperationStoreError> {
    no_output(record)?;
    let header: (Option<String>, Option<String>) = tx.query_row(
        "SELECT native_namespace,native_request FROM admission_operation_recovery_records WHERE record_key=?1",
        [workflow_key(&record.scope, &record.workflow_id)?], |row| Ok((row.get(0)?, row.get(1)?)),
    ).map_err(sqlite_error)?;
    let Some(action) = record.action.as_ref() else {
        if header != (None, None)
            || record.process_reservation.is_some()
            || record.admission.is_some()
            || record.native_link.is_some()
            || record.review.is_some()
            || record.approval.is_some()
            || record.issuance.is_some()
            || record.signed_grant.is_some()
            || record.envelope.is_some()
            || record.original_flow.is_some()
            || record.effect != EffectObservationV1::NeverAdmitted
        {
            return Err(invariant(
                "unmaterialized closure has native or process custody",
            ));
        }
        super::super::workflow_reservations::require_unmaterialized_no_native_accounting(
            tx, record,
        )?;
        return Ok(ContinuationClosure::Unmaterialized);
    };
    let reserved = reservation(record)?;
    let namespace = hex(action.request_namespace.as_bytes());
    if header.0.as_deref() != Some(namespace.as_str())
        || header.1.as_deref() != Some(action.request_id.as_str())
    {
        return Err(invariant(
            "original closure lost its materialized native lookup",
        ));
    }
    if let Some(intent) = &record.admission {
        let id = AdmissionOperationId::from_persisted(intent.native_operation_id.as_str())?;
        let stored = load_by_operation_id_tx(tx, &id)?
            .ok_or_else(|| invariant("admitted original closure lost its native operation"))?;
        let operation = &stored.operation;
        let reference = native::operation_ref(operation)?;
        if operation.state() != AdmissionOperationState::CompensatedBeforeDispatch
            || operation.dispatch_commit().is_some()
            || operation.binding().to_persisted() != intent.native_binding
            || operation.binding().request_namespace_digest().as_str() != namespace
            || operation.binding().request_id().as_str() != action.request_id.as_str()
            || record.native_link.as_ref().map(OperationId::as_str) != Some(id.as_str())
            || !matches!(&record.effect, EffectObservationV1::ClosedBeforeEffect { operation, .. } if *operation == reference)
        {
            return Err(invariant(
                "native continuation has no authenticated before-dispatch closure",
            ));
        }
        crate::admission_operation_store::projection::verify_stored_terminal_projection(
            tx, &stored,
        )?;
        let retained: RetainedToolAdmissionRequestV1 =
            crate::admission_operation_store::retained_request::load_retained_request_tx(
                tx, operation,
            )?
            .ok_or_else(|| invariant("compensated continuation lost its retained request"))?;
        let envelope = record
            .envelope
            .as_ref()
            .ok_or_else(|| invariant("compensated continuation lost its envelope"))?;
        let request: ToolCallRequest = decode(envelope.request.as_str().as_bytes())?;
        retained.validate_request_material(&request)?;
        return Ok(ContinuationClosure::Compensated {
            operation: reference,
            retained_request_digest: CanonicalPayloadDigest::from_bytes(
                *chio_core::sha256(retained.canonical_bytes()).as_bytes(),
            ),
            reservation_digest: reserved,
        });
    }
    if record.native_link.is_some()
        || record.issuance.is_some()
        || record.signed_grant.is_some()
        || record.envelope.is_some()
        || record.effect != EffectObservationV1::NeverAdmitted
    {
        return Err(invariant(
            "materialized closure retains an unclosed issuance or admission",
        ));
    }
    // A current-table miss cannot close an acknowledged Process reservation.
    // Materialized retirement remains unavailable until the native/Process
    // owner supplies its authenticated historical no-future obligation proof.
    Err(invariant(
        "materialized original lacks an authenticated closed native admission",
    ))
}

fn authenticate_original(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let original = record
        .origin
        .as_ref()
        .ok_or_else(|| invariant("no-future admission lacks its original denial"))?;
    let request: ToolCallRequest =
        chio_core_types::recovery::decode_contract(record.creation_seed.as_str().as_bytes())
            .map_err(|_| invariant("no-future admission original seed refused"))?;
    let id = AdmissionOperationId::from_persisted(
        original.operation.operation_id().as_str().to_owned(),
    )?;
    let stored = load_by_operation_id_tx(tx, &id)?
        .ok_or_else(|| invariant("unused original native denial disappeared"))?;
    stored.verify_decision_time(now)?;
    let operation = &stored.operation;
    let retained = crate::admission_operation_store::retained_request::load_retained_request_tx(
        tx, operation,
    )?
    .ok_or_else(|| invariant("unused original lost its retained native request"))?;
    let authority = retained
        .native_security_authority_binding()
        .ok_or_else(|| invariant("unused original has no authenticated native authority"))?;
    let namespace =
        chio_kernel::admission_operation::AuthenticatedRequestNamespace::for_local_system(
            authority.store_uuid().clone(),
        )?;
    if authority.store_uuid().as_str() != record.scope.authority_domain.as_str()
        || operation.binding().request_namespace_digest() != namespace.digest()
        || operation.binding().kind() != AdmissionOperationKind::ToolDispatch
        || operation.state() != AdmissionOperationState::CompensatedBeforeDispatch
        || operation.dispatch_commit().is_some()
        || native::operation_ref(operation)? != original.operation
        || operation.binding().request_id().as_str() != original.request_id.as_str()
        || original.request_id.as_str() != request.request_id
        || original.closure.as_str() != format!("closure:{}", id.as_str())
    {
        return Err(invariant(
            "unused original has no authentic before-dispatch native denial",
        ));
    }
    retained.validate_request_material(&request)?;
    crate::admission_operation_store::projection::verify_stored_terminal_projection(tx, &stored)
}

pub(super) fn verify_unused_native_custody(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
    now: u64,
) -> Result<ContinuationClosure, AdmissionOperationStoreError> {
    authenticate_original(tx, record, now)?;
    continuation_closure(tx, record)
}

pub(super) fn authenticate_closed<'owner, 'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    owner: &'owner SqliteServingOwner,
    cut: &NativeSourceTransactionOrigin<'owner>,
    record: &RecoveryWorkflowRecordV1,
    now: u64,
) -> Result<AuthenticatedNoFutureNativeAdmission<'owner, 'tx, 'conn>, AdmissionOperationStoreError>
{
    cut.verify(tx).map_err(map_owner_error)?;
    if !cut.matches_owner(owner) {
        return Err(invariant("original closure changed its serving owner"));
    }
    schema::verify_active_owner(tx, owner, Some(&owner.fence))?;
    if !eligible(record) {
        return Err(invariant(
            "original owner is not conclusively closed before dispatch",
        ));
    }
    historical_holds::require_unheld(tx, record)?;
    let key = workflow_key(&record.scope, &record.workflow_id)?;
    let row = raw_checked(tx, &key)?
        .ok_or_else(|| invariant("original closure lost its physical record"))?;
    if row.payload != encode(record)?
        || row.version != record.revision.get()
        || row.kind != "workflow"
        || row.scope != scope_key(&record.scope)?
        || record.scope.authority_domain.as_str() != owner.fence.store_uuid
    {
        return Err(invariant("original closure changed its actual workflow"));
    }
    authenticate_original(tx, record, now)?;
    let continuation = continuation_closure(tx, record)?;
    let proof = AuthenticatedNoFutureNativeAdmission {
        tx,
        owner,
        cut: cut.fork_for_source(),
        record: Box::new(record.clone()),
        workflow: SourceVersion::capture(&source_reference(tx, &key)?)?,
        quota: SourceVersion::capture(&source_reference(
            tx,
            &quota_key(&record.scope, &record.workflow_id)?,
        )?)?,
        continuation,
        now,
    };
    proof.verify(tx)?;
    Ok(proof)
}

impl<'owner, 'tx, 'conn> AuthenticatedNoFutureNativeAdmission<'owner, 'tx, 'conn> {
    pub(in crate::admission_operation_store) fn record(&self) -> &RecoveryWorkflowRecordV1 {
        &self.record
    }
    pub(in crate::admission_operation_store) fn matches_owner(
        &self,
        owner: &SqliteServingOwner,
    ) -> bool {
        self.cut.matches_owner(owner) && std::ptr::eq(self.owner, owner)
    }
    pub(in crate::admission_operation_store) fn verify(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq::<Connection>(&**self.tx, &**tx) {
            return Err(invariant(
                "original closure changed its physical transaction",
            ));
        }
        self.cut.verify(tx).map_err(map_owner_error)?;
        if !self.cut.matches_owner(self.owner) {
            return Err(invariant("original closure changed owner custody"));
        }
        self.workflow.current(
            tx,
            &workflow_key(&self.record.scope, &self.record.workflow_id)?,
        )?;
        self.quota.current(
            tx,
            &quota_key(&self.record.scope, &self.record.workflow_id)?,
        )?;
        authenticate_original(tx, &self.record, self.now)?;
        if !eligible(&self.record) || continuation_closure(tx, &self.record)? != self.continuation {
            return Err(invariant(
                "original closure changed its native no-future evidence",
            ));
        }
        Ok(())
    }
}

pub(super) fn closure_body(
    proof: &AuthenticatedNoFutureNativeAdmission<'_, '_, '_>,
    head: &OwnerHead,
    head_source: &SourceVersion,
    allocation: SourceVersion,
) -> Result<OwnerClosure, AdmissionOperationStoreError> {
    proof.verify(proof.tx)?;
    Ok(OwnerClosure {
        schema: ClosureSchema::V1,
        scope: proof.record.scope.clone(),
        workflow_id: proof.record.workflow_id.clone(),
        original: proof
            .record
            .origin
            .clone()
            .ok_or_else(|| invariant("original closure provenance disappeared"))?,
        original_claim: head.original_claim.clone(),
        original_head: head_source.clone(),
        owner_ordinal: head.owner_ordinal,
        workflow: proof.workflow.clone(),
        quota: proof.quota.clone(),
        allocation,
        sealed_at_unix_ms: safe(proof.now)?,
        continuation_closure: proof.continuation.clone(),
    })
}

pub(super) fn verify_retained_closure(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
    closure: &OwnerClosure,
) -> Result<(), AdmissionOperationStoreError> {
    if !eligible(record)
        || record.scope != closure.scope
        || record.workflow_id != closure.workflow_id
        || record.origin.as_ref() != Some(&closure.original)
    {
        return Err(invariant(
            "retained original closure changed its frozen owner",
        ));
    }
    closure
        .workflow
        .current(tx, &workflow_key(&record.scope, &record.workflow_id)?)?;
    closure
        .quota
        .current(tx, &quota_key(&record.scope, &record.workflow_id)?)?;
    closure
        .allocation
        .current(tx, &allocation_key(&record.scope, &record.workflow_id)?)?;
    super::super::active_workflows::require_no_future_retired_allocation(tx, record)?;
    authenticate_original(tx, record, closure.sealed_at_unix_ms.get())?;
    if continuation_closure(tx, record)? != closure.continuation_closure {
        return Err(invariant(
            "retained original closure changed its native evidence",
        ));
    }
    Ok(())
}
