//! Closed native source proofs finance only their exact logical custody change.
use super::*;
use crate::admission_operation_store::knowledge::reference_source::{
    VerifiedKnowledgeReferenceRetain, VerifiedKnowledgeReferenceRetirement,
};
use crate::admission_operation_store::knowledge::references::{
    prepare_reference_retain, prepare_reference_retirement,
};
use std::collections::BTreeSet;

#[derive(Clone, Copy)]
enum KnowledgeReferencePurpose {
    Retain,
    Retire,
    ProductProposalRetire,
}

/// The actual owning source is already saved in this same transaction. A
/// refusal rolls back that source and every prospective custody write with it.
/// This logical admission does not supply physical finishing credits.
pub(in crate::admission_operation_store) fn persist_knowledge_reference_retain<'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    owner: &SqliteServingOwner,
    proof: VerifiedKnowledgeReferenceRetain<'tx, 'conn>,
) -> Result<ProtectedMutationDelta, AdmissionOperationStoreError> {
    same_writer(proof.transaction(), tx)?;
    proof.verify(tx)?;
    require_retain_owner(proof.owner())?;
    let plan = prepare_reference_retain(tx, proof)?;
    persist_progress(tx, owner, plan, KnowledgeReferencePurpose::Retain)
}

/// Only a genuine irreversible native terminal source can release ownership.
/// Logical reference retirement refunds no artifact or physical byte allocation.
pub(in crate::admission_operation_store) fn persist_knowledge_reference_retirement<'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    owner: &SqliteServingOwner,
    proof: VerifiedKnowledgeReferenceRetirement<'tx, 'conn>,
) -> Result<ProtectedMutationDelta, AdmissionOperationStoreError> {
    same_writer(proof.transaction(), tx)?;
    proof.verify(tx)?;
    require_retirement_owner(proof.owner())?;
    let plan = prepare_reference_retirement(tx, proof)?;
    persist_progress(tx, owner, plan, KnowledgeReferencePurpose::Retire)
}

/// Product retirement consumes its own current affine terminal evidence. It
/// cannot select ordinary Knowledge retirement or refund intake/byte credits.
pub(in crate::admission_operation_store) fn persist_product_reference_retirement<'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    owner: &SqliteServingOwner,
    proof: VerifiedKnowledgeReferenceRetirement<'tx, 'conn>,
) -> Result<ProtectedMutationDelta, AdmissionOperationStoreError> {
    same_writer(proof.transaction(), tx)?;
    proof.verify_product_proposal_retirement(tx)?;
    if !matches!(proof.owner(), ReferenceOwner::ProductProposal { .. }) {
        return Err(invariant(
            "Product retirement cannot select another participant",
        ));
    }
    let plan = prepare_reference_retirement(tx, proof)?;
    persist_progress(
        tx,
        owner,
        plan,
        KnowledgeReferencePurpose::ProductProposalRetire,
    )
}

fn require_retain_owner(owner: &ReferenceOwner) -> Result<(), AdmissionOperationStoreError> {
    match owner {
        ReferenceOwner::Publication { .. }
        | ReferenceOwner::CheckpointRevision { .. }
        | ReferenceOwner::OperatorPin { .. }
        | ReferenceOwner::NativeOperation { .. }
        | ReferenceOwner::PendingApproval { .. }
        | ReferenceOwner::ArtifactRelease { .. }
        | ReferenceOwner::CheckpointRestore { .. }
        | ReferenceOwner::ConfinedInputs { .. } => Ok(()),
        ReferenceOwner::ProductReport { .. }
        | ReferenceOwner::ProductProposal { .. }
        | ReferenceOwner::ArchivePreparation { .. }
        | ReferenceOwner::ArchiveDelivery { .. }
        | ReferenceOwner::LegacyPinSource { .. } => Err(invariant(
            "knowledge intake cannot borrow another participant's source",
        )),
    }
}

fn require_retirement_owner(owner: &ReferenceOwner) -> Result<(), AdmissionOperationStoreError> {
    match owner {
        ReferenceOwner::Publication { .. }
        | ReferenceOwner::CheckpointRevision { .. }
        | ReferenceOwner::OperatorPin { .. }
        | ReferenceOwner::ArtifactRelease { .. }
        | ReferenceOwner::CheckpointRestore { .. } => Ok(()),
        ReferenceOwner::NativeOperation { .. }
        | ReferenceOwner::ConfinedInputs { .. }
        | ReferenceOwner::PendingApproval { .. }
        | ReferenceOwner::ProductReport { .. }
        | ReferenceOwner::ProductProposal { .. }
        | ReferenceOwner::ArchivePreparation { .. }
        | ReferenceOwner::ArchiveDelivery { .. }
        | ReferenceOwner::LegacyPinSource { .. } => Err(invariant(
            "knowledge retirement has no terminal authority for this owner",
        )),
    }
}

fn persist_progress<'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    owner: &SqliteServingOwner,
    plan: PreparedReferenceUpdates<'tx, 'conn>,
    purpose: KnowledgeReferencePurpose,
) -> Result<ProtectedMutationDelta, AdmissionOperationStoreError> {
    require_reference_format(tx)?;
    crate::admission_operation_store::schema::verify_active_owner(tx, owner, Some(&owner.fence))?;
    same_writer(plan.transaction(), tx)?;
    plan.verify_current(tx)?;
    if plan.scope().authority_domain.as_str() != owner.fence.store_uuid
        || plan.owner_source().scope_key() != scope_key(plan.scope())?
        || plan.owner_source().kind() != "command"
        || plan.reference_count() > chio_security_types::knowledge::MAX_ARTIFACT_TRAVERSAL
    {
        return Err(invariant("knowledge reference changed its native account"));
    }
    for (index, reference) in plan.references().iter().enumerate() {
        let local = match purpose {
            KnowledgeReferencePurpose::Retain | KnowledgeReferencePurpose::Retire => {
                reference.scope == *plan.scope()
            }
            KnowledgeReferencePurpose::ProductProposalRetire => {
                reference.scope.authority_domain == plan.scope().authority_domain
                    && reference.scope.tenant_id == plan.scope().tenant_id
            }
        };
        if !local || plan.references()[..index].contains(reference) {
            return Err(invariant(
                "knowledge reference crossed scope or repeated governed custody",
            ));
        }
    }
    if plan.reference_count() == 0 {
        let footprint = plan.write_footprint();
        if !plan.staged_updates().is_empty()
            || footprint.record_count() != 0
            || footprint.event_count() != 0
            || footprint.encoded_bytes() != 0
            || footprint.new_active_owners() != 0
            || footprint.retired_active_owners() != 0
        {
            return Err(invariant("empty owning source acquired reference work"));
        }
        return Ok(ProtectedMutationDelta::zero());
    }
    let (mut account, capacity, ready) = require_ready_capacity(tx, plan.scope())?;
    verify_source_reference(tx, &capacity)?;
    verify_source_reference(tx, &ready)?;
    verify_source_reference(tx, plan.owner_source())?;
    let footprint = plan.write_footprint();
    let maximum = plan
        .reference_count()
        .checked_mul(3)
        .ok_or_else(|| invariant("knowledge reference write bound overflow"))?;
    let references = u64::try_from(plan.reference_count())
        .map_err(|_| invariant("knowledge reference count overflow"))?;
    let admitted = footprint.new_active_owners();
    let retired = footprint.retired_active_owners();
    let changed = match purpose {
        KnowledgeReferencePurpose::Retain if retired == 0 && admitted <= references => admitted,
        KnowledgeReferencePurpose::Retire | KnowledgeReferencePurpose::ProductProposalRetire
            if admitted == 0 && retired <= references =>
        {
            retired
        }
        _ => {
            return Err(invariant(
                "knowledge reference changed its accepted purpose",
            ))
        }
    };
    if footprint.record_count() != plan.staged_updates().len()
        || footprint.event_count() != footprint.record_count()
        || footprint.record_count() > maximum
        || (changed == 0) != plan.staged_updates().is_empty()
    {
        return Err(invariant(
            "knowledge reference changed its complete footprint",
        ));
    }
    let mut classes = BTreeSet::new();
    let mut bytes = 0_u64;
    for write in plan.staged_updates() {
        let class =
            super::reference_product::ordinary_slot(write, plan.references(), plan.owner())?;
        if !classes.insert(class) {
            return Err(invariant(
                "knowledge reference repeated an exact target slot",
            ));
        }
        bytes = bytes
            .checked_add(
                u64::try_from(write.payload().len())
                    .map_err(|_| invariant("knowledge reference byte count overflow"))?,
            )
            .ok_or_else(|| invariant("knowledge reference byte count overflow"))?;
    }
    if usize::try_from(bytes).ok() != Some(footprint.encoded_bytes()) {
        return Err(invariant(
            "knowledge reference changed its encoded footprint",
        ));
    }
    if changed == 0 {
        return Ok(ProtectedMutationDelta::zero());
    }
    match purpose {
        KnowledgeReferencePurpose::Retain => {
            if account
                .active()?
                .checked_add(admitted)
                .is_none_or(|active| active > MAX_ACTIVE_REFERENCE_OWNERS)
            {
                return Err(invariant("reference tenant active quota exhausted"));
            }
            crate::admission_operation_store::recovery::resources::check_intake_committing(tx)?;
            account.admitted = account
                .admitted
                .checked_add(admitted)
                .ok_or_else(|| invariant("reference admitted counter exhausted"))?;
        }
        KnowledgeReferencePurpose::Retire | KnowledgeReferencePurpose::ProductProposalRetire => {
            if retired > account.active()? {
                return Err(invariant("reference retirement exceeds original ownership"));
            }
            crate::admission_operation_store::recovery::resources::check_committing(tx)?;
            account.retired = account
                .retired
                .checked_add(retired)
                .ok_or_else(|| invariant("reference retired counter exhausted"))?;
        }
    }
    account.batches = account
        .batches
        .checked_add(1)
        .ok_or_else(|| invariant("reference batch counter exhausted"))?;
    plan.verify_current(tx)?;
    let (_, current_capacity, current_ready) = require_ready_capacity(tx, plan.scope())?;
    if !same_source(&capacity, &current_capacity) || !same_source(&ready, &current_ready) {
        return Err(invariant(
            "knowledge reference lost its exact account heads",
        ));
    }
    let before = global_head(tx)?;
    for write in plan.staged_updates() {
        persist_update(tx, owner, write, ORDINARY_REFERENCE_BYTES)?;
    }
    let (_, account_bytes) = save_capacity(tx, owner, plan.scope(), &account, Some(&capacity))?;
    bytes = bytes
        .checked_add(account_bytes)
        .ok_or_else(|| invariant("knowledge reference byte count overflow"))?;
    let mutations = u64::try_from(footprint.record_count())
        .map_err(|_| invariant("knowledge reference mutation count overflow"))?
        .checked_add(1)
        .ok_or_else(|| invariant("knowledge reference mutation count overflow"))?;
    let after = global_head(tx)?;
    if before.sequence.checked_add(mutations) != Some(after.sequence) {
        return Err(invariant(
            "knowledge reference contains an unaccepted protected mutation",
        ));
    }
    Ok(ProtectedMutationDelta {
        mutations,
        encoded_bytes: bytes,
    })
}
