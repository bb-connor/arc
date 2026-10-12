//! Fresh original ownership consumes one authenticated closed predecessor.
use super::*;

enum PreviousOwner<'owner, 'tx, 'conn> {
    First,
    Closed {
        head: OwnerHead,
        source: SourceVersion,
        proof: AuthenticatedNoFutureNativeAdmission<'owner, 'tx, 'conn>,
    },
}

pub(in crate::admission_operation_store) struct PreparedOriginalOwnerCreation<'owner, 'tx, 'conn> {
    tx: &'tx Transaction<'conn>,
    owner: &'owner SqliteServingOwner,
    cut: NativeSourceTransactionOrigin<'owner>,
    actor: &'tx AuthenticatedRecoveryActor,
    deployment: &'tx RecoveryDeploymentV1,
    profile_source: SourceVersion,
    proposed: RecoveryWorkflowRecordV1,
    previous: PreviousOwner<'owner, 'tx, 'conn>,
    sealed: Option<SourceVersion>,
    now: u64,
}

pub(in crate::admission_operation_store) fn prepare_original_owner_creation<'owner, 'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    writer: (
        &'owner SqliteServingOwner,
        &NativeSourceTransactionOrigin<'owner>,
    ),
    actor: &'tx AuthenticatedRecoveryActor,
    deployment: &'tx RecoveryDeploymentV1,
    proposed: &RecoveryWorkflowRecordV1,
    now: u64,
) -> Result<PreparedOriginalOwnerCreation<'owner, 'tx, 'conn>, RecoveryCommandPortError> {
    let (owner, cut) = writer;
    require_format(tx)?;
    cut.verify(tx).map_err(map_owner_error)?;
    schema::verify_active_owner(tx, owner, Some(&owner.fence))?;
    verify_actor(tx, actor, deployment, now)?;
    if !cut.matches_owner(owner)
        || actor.permission() != RecoveryPermission::Create
        || proposed.scope != *actor.scope()
        || proposed.created_by != *actor.principal()
        || proposed.scope.authority_domain.as_str() != owner.fence.store_uuid
        || proposed.control != WorkflowControlV1::Active
        || proposed.revision.get() != 1
        || proposed.admission_closed
        || proposed.action.is_some()
        || proposed.process_reservation.is_some()
        || proposed.selected
        || proposed.review.is_some()
        || proposed.approval.is_some()
        || proposed.issuance.is_some()
        || proposed.signed_grant.is_some()
        || proposed.envelope.is_some()
        || proposed.admission.is_some()
        || proposed.native_link.is_some()
        || proposed.captured
        || proposed.captured_deployment.is_some()
        || proposed.historical_hold.is_some()
        || proposed.effect != EffectObservationV1::NeverAdmitted
        || proposed.release != ReleaseDispositionV1::NotAvailable
        || proposed.original_flow.is_some()
        || proposed.reported_decision.is_some()
        || proposed.provider_finality.is_some()
        || proposed.provider_lookups != SafeInteger::ZERO
        || raw_checked(tx, &workflow_key(&proposed.scope, &proposed.workflow_id)?)?.is_some()
    {
        return Err(invariant("new original owner is not a fresh authenticated creation").into());
    }
    validate_seed(&proposed.seed, deployment)?;
    let origin = proposed
        .origin
        .as_ref()
        .ok_or_else(|| invariant("new original owner lacks its native denial"))?;
    original_resolution::revalidate(tx, &proposed.seed, deployment, now, origin)?;
    let profile_source = SourceVersion::capture(&source_reference(
        tx,
        &format!("deployment:{}", scope_key(actor.scope())?),
    )?)?;
    let previous = if raw_checked(tx, &origins::claim_key(origin)?)?.is_none() {
        if raw_checked(tx, &head_key(origin)?)?.is_some() {
            return Err(invariant(
                "pristine original retains a current owner without its first claim",
            )
            .into());
        }
        PreviousOwner::First
    } else {
        let (head, source) = history::load_head(tx, origin)?;
        if head.scope != proposed.scope
            || head.current_owner.created_by != proposed.created_by
            || head.current_owner.workflow_id == proposed.workflow_id
        {
            return Err(RecoveryCommandPortError::Conflict);
        }
        let prior = workflow_tx(tx, &head.scope, &head.current_owner.workflow_id)?;
        if descriptor(tx, &prior)? != head.current_owner
            || prior.creation_seed != proposed.creation_seed
            || prior.origin.as_ref() != Some(origin)
            || !no_future_admission::eligible(&prior)
            || raw_checked(tx, &closure_key(&prior.scope, &prior.workflow_id)?)?.is_some()
        {
            return Err(RecoveryCommandPortError::Conflict);
        }
        let proof = no_future_admission::authenticate_closed(tx, owner, cut, &prior, now)?;
        PreviousOwner::Closed {
            head,
            source,
            proof,
        }
    };
    Ok(PreparedOriginalOwnerCreation {
        tx,
        owner,
        cut: cut.fork_for_source(),
        actor,
        deployment,
        profile_source,
        proposed: proposed.clone(),
        previous,
        sealed: None,
        now,
    })
}

impl PreparedOriginalOwnerCreation<'_, '_, '_> {
    fn verify_fresh(
        &self,
        tx: &Transaction<'_>,
        owner: &SqliteServingOwner,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq::<Connection>(&**self.tx, &**tx)
            || !std::ptr::eq(self.owner, owner)
            || !self.cut.matches_owner(owner)
        {
            return Err(invariant("original creation changed its actual writer"));
        }
        self.cut.verify(tx).map_err(map_owner_error)?;
        self.profile_source.current(
            tx,
            &format!("deployment:{}", scope_key(&self.proposed.scope)?),
        )?;
        verify_actor(tx, self.actor, self.deployment, self.now)?;
        original_resolution::revalidate(
            tx,
            &self.proposed.seed,
            self.deployment,
            self.now,
            self.proposed
                .origin
                .as_ref()
                .ok_or_else(|| invariant("original creation lost native provenance"))?,
        )?;
        Ok(())
    }
}

/// Closure is committed before the successor is allocated. No old workflow,
/// quota, reservation, command identity, history or process debit is removed.
pub(in crate::admission_operation_store) fn seal_original_owner_predecessor(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    prepared: &mut PreparedOriginalOwnerCreation<'_, '_, '_>,
) -> Result<ProtectedMutationDelta, RecoveryCommandPortError> {
    prepared.verify_fresh(tx, owner)?;
    if prepared.sealed.is_some() {
        return Err(invariant("original predecessor closure was already consumed").into());
    }
    super::super::super::resources::check_intake_committing(tx)?;
    let before = global_sequence(tx)?;
    let origin = prepared
        .proposed
        .origin
        .as_ref()
        .ok_or_else(|| invariant("original closure lost native provenance"))?;
    let sealed = match &prepared.previous {
        PreviousOwner::First => {
            origins::claim(tx, owner, &prepared.proposed)?;
            SourceVersion::capture(&origins::load_immutable_claim(tx, origin)?.1)?
        }
        PreviousOwner::Closed {
            head,
            source,
            proof,
        } => {
            source.current(tx, &head_key(origin)?)?;
            proof.verify(tx)?;
            super::super::active_workflows::retire_no_future_native_admission(tx, owner, proof)?;
            let allocation = SourceVersion::capture(&source_reference(
                tx,
                &allocation_key(&proof.record().scope, &proof.record().workflow_id)?,
            )?)?;
            let closure = no_future_admission::closure_body(proof, head, source, allocation)?;
            let key = closure_key(&closure.scope, &closure.workflow_id)?;
            if raw_checked(tx, &key)?.is_some() {
                return Err(invariant("original owner already has an immutable closure").into());
            }
            persist(tx, owner, &prepared.cut, &key, &closure.scope, &closure)?.0
        }
    };
    prepared.sealed = Some(sealed);
    actual_delta_since(tx, before).map_err(Into::into)
}

/// Publication consumes the exact fresh physical successor and closed sources.
pub(in crate::admission_operation_store) fn publish_original_owner_creation(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    prepared: PreparedOriginalOwnerCreation<'_, '_, '_>,
    record: &RecoveryWorkflowRecordV1,
) -> Result<ProtectedMutationDelta, AdmissionOperationStoreError> {
    prepared.verify_fresh(tx, owner)?;
    if encode(record)? != encode(&prepared.proposed)? {
        return Err(invariant(
            "original successor changed its prepared pristine workflow",
        ));
    }
    let successor = descriptor(tx, record)?;
    let sealed = prepared
        .sealed
        .ok_or_else(|| invariant("original publication lacks its consumed predecessor closure"))?;
    let origin = record
        .origin
        .as_ref()
        .ok_or_else(|| invariant("original successor lost native provenance"))?;
    let before = global_sequence(tx)?;
    let head = match prepared.previous {
        PreviousOwner::First => {
            sealed.current(tx, &origins::claim_key(origin)?)?;
            history::initial_head(&sealed, &successor, &record.scope)?
        }
        PreviousOwner::Closed {
            head,
            source,
            proof,
        } => {
            source.current(tx, &head_key(origin)?)?;
            sealed.current(
                tx,
                &closure_key(&proof.record().scope, &proof.record().workflow_id)?,
            )?;
            proof.verify(tx)?;
            let ordinal = head
                .owner_ordinal
                .get()
                .checked_add(1)
                .ok_or_else(|| invariant("original owner succession exhausted"))?;
            let key = transfer_key(origin, ordinal)?;
            if raw_checked(tx, &key)?.is_some() {
                return Err(invariant("original successor ordinal was already consumed"));
            }
            let transfer = OwnerTransfer {
                schema: TransferSchema::V1,
                scope: head.scope.clone(),
                original_claim: head.original_claim.clone(),
                previous_head: source,
                previous_owner_ordinal: head.owner_ordinal,
                previous_owner: head.current_owner.clone(),
                closure: sealed,
                successor_owner_ordinal: safe(ordinal)?,
                successor: successor.clone(),
            };
            let transfer_source =
                persist(tx, owner, &prepared.cut, &key, &record.scope, &transfer)?.0;
            OwnerHead {
                owner_ordinal: safe(ordinal)?,
                current_owner: successor,
                last_transfer: Some(transfer_source),
                ..head
            }
        }
    };
    persist(
        tx,
        owner,
        &prepared.cut,
        &head_key(origin)?,
        &record.scope,
        &head,
    )?;
    let (readback, _) = history::load_head(tx, origin)?;
    if readback != head {
        return Err(invariant(
            "original owner publication lost its exact successor",
        ));
    }
    actual_delta_since(tx, before)
}
