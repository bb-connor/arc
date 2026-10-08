//! A private pre-append intake becomes an allowance only after its real source exists.
use super::*;
use std::collections::BTreeSet;

pub(in crate::admission_operation_store) struct ReservedProductReferenceIntake<'tx, 'conn> {
    proof: VerifiedProductReferenceIntake<'tx, 'conn>,
    capacity: ProtectedSourceReference,
    ready: ProtectedSourceReference,
}

pub(in crate::admission_operation_store) fn reserve_product_reference_intake<'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    owner: &SqliteServingOwner,
    proof: VerifiedProductReferenceIntake<'tx, 'conn>,
) -> Result<Option<ReservedProductReferenceIntake<'tx, 'conn>>, AdmissionOperationStoreError> {
    same_writer(proof.transaction(), tx)?;
    proof.verify(tx)?;
    // An attachment-free report has no knowledge custody or account admission.
    if proof.references().is_empty() {
        return Ok(None);
    }
    require_reference_format(tx)?;
    crate::admission_operation_store::schema::verify_active_owner(tx, owner, Some(&owner.fence))?;
    if proof.scope().authority_domain.as_str() != owner.fence.store_uuid {
        return Err(invariant(
            "product reference intake changed its serving domain",
        ));
    }
    verify_complete_product_set(&proof)?;
    let (account, capacity, ready) = require_ready_capacity(tx, proof.scope())?;
    let additional = u64::try_from(proof.references().len())
        .map_err(|_| invariant("product reference count overflow"))?;
    if account
        .active()?
        .checked_add(additional)
        .is_none_or(|active| active > MAX_ACTIVE_REFERENCE_OWNERS)
    {
        return Err(invariant("reference tenant active quota exhausted"));
    }
    crate::admission_operation_store::recovery::resources::check_intake_committing(tx)?;
    Ok(Some(ReservedProductReferenceIntake {
        proof,
        capacity,
        ready,
    }))
}

fn verify_complete_product_set(
    proof: &VerifiedProductReferenceIntake<'_, '_>,
) -> Result<(), AdmissionOperationStoreError> {
    let (scope, maximum) = match proof.owner() {
        ProductEvidenceOwner::Report { scope, .. } => (scope, 8),
        ProductEvidenceOwner::Proposal { scope, .. } => (scope, 32),
    };
    if scope != proof.scope()
        || proof.source_key().is_empty()
        || proof.source_key().len() > 512
        || proof.source_scope_key() != scope_key(scope)?
        || proof.references().len() > maximum
    {
        return Err(invariant(
            "product intake changed its complete source identity",
        ));
    }
    for (index, reference) in proof.references().iter().enumerate() {
        if !same_account(scope, &reference.scope) || proof.references()[..index].contains(reference)
        {
            return Err(invariant(
                "product reference intake is foreign or duplicated",
            ));
        }
    }
    Ok(())
}

/// Private fields and the genuine source factory supply authority; keys do not.
pub(in crate::admission_operation_store) struct VerifiedParticipantAllowance<'tx, 'conn> {
    proof: VerifiedProductReferenceIntake<'tx, 'conn>,
    parent: ProtectedSourceReference,
    capacity: ProtectedSourceReference,
    ready: ProtectedSourceReference,
    owner: ReferenceOwner,
}

pub(in crate::admission_operation_store) fn bind_product_reference_source<'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    reserved: ReservedProductReferenceIntake<'tx, 'conn>,
    actual: &ProtectedSourceReference,
) -> Result<VerifiedParticipantAllowance<'tx, 'conn>, AdmissionOperationStoreError> {
    same_writer(reserved.proof.transaction(), tx)?;
    reserved.proof.verify_saved_source(tx, actual)?;
    verify_complete_product_set(&reserved.proof)?;
    verify_source_reference(tx, &reserved.capacity)?;
    verify_source_reference(tx, &reserved.ready)?;
    let parent = source_reference(tx, actual.record_key())?;
    if !same_source(actual, &parent) {
        return Err(invariant(
            "product reference binding changed the actual saved source",
        ));
    }
    let owner = reserved.proof.owner().clone().into();
    let bound = VerifiedParticipantAllowance {
        proof: reserved.proof,
        parent,
        capacity: reserved.capacity,
        ready: reserved.ready,
        owner,
    };
    bound.verify(tx)?;
    Ok(bound)
}

impl<'conn> VerifiedParticipantAllowance<'_, 'conn> {
    fn verify(&self, tx: &Transaction<'conn>) -> Result<(), AdmissionOperationStoreError> {
        same_writer(self.proof.transaction(), tx)?;
        self.proof.verify_saved_source(tx, &self.parent)?;
        verify_complete_product_set(&self.proof)?;
        verify_source_reference(tx, &self.capacity)?;
        verify_source_reference(tx, &self.ready)?;
        if self.owner != ReferenceOwner::from(self.proof.owner().clone()) {
            return Err(invariant("product allowance changed its closed owner"));
        }
        let (_, capacity, ready) = require_ready_capacity(tx, self.proof.scope())?;
        if !same_source(&capacity, &self.capacity) || !same_source(&ready, &self.ready) {
            return Err(invariant("product allowance lost its exact account heads"));
        }
        Ok(())
    }
}

pub(in crate::admission_operation_store) fn persist_knowledge_reference_progress<'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    owner: &SqliteServingOwner,
    plan: PreparedReferenceUpdates<'tx, 'conn>,
    allowance: VerifiedParticipantAllowance<'tx, 'conn>,
) -> Result<ProtectedMutationDelta, AdmissionOperationStoreError> {
    require_reference_format(tx)?;
    crate::admission_operation_store::schema::verify_active_owner(tx, owner, Some(&owner.fence))?;
    same_writer(plan.transaction(), tx)?;
    allowance.verify(tx)?;
    plan.verify_current(tx)?;
    if plan.scope() != allowance.proof.scope()
        || plan.owner() != &allowance.owner
        || !same_source(plan.owner_source(), &allowance.parent)
        || plan.references() != allowance.proof.references()
        || plan.reference_count() != allowance.proof.references().len()
    {
        return Err(invariant(
            "product allowance was applied to a different complete plan",
        ));
    }
    let footprint = plan.write_footprint();
    let maximum = plan
        .reference_count()
        .checked_mul(3)
        .ok_or_else(|| invariant("product reference write bound overflow"))?;
    let reference_count = u64::try_from(plan.reference_count())
        .map_err(|_| invariant("product reference count overflow"))?;
    if footprint.record_count() != plan.staged_updates().len()
        || footprint.event_count() != footprint.record_count()
        || footprint.record_count() > maximum
        || footprint.new_active_owners() > reference_count
        || footprint.retired_active_owners() != 0
    {
        return Err(invariant(
            "product reference plan changed its accepted purpose or footprint",
        ));
    }
    let mut classes = BTreeSet::new();
    let mut bytes = 0_u64;
    for write in plan.staged_updates() {
        let class = ordinary_slot(write, plan.references(), plan.owner())?;
        if !classes.insert(class) {
            return Err(invariant("product reference plan repeated a closed slot"));
        }
        bytes = bytes
            .checked_add(
                u64::try_from(write.payload().len())
                    .map_err(|_| invariant("reference encoded byte count overflow"))?,
            )
            .ok_or_else(|| invariant("reference encoded byte count overflow"))?;
    }
    if usize::try_from(bytes).ok() != Some(footprint.encoded_bytes()) {
        return Err(invariant(
            "product reference plan changed its encoded footprint",
        ));
    }
    let (mut account, account_source) = load_capacity(tx, plan.scope())?;
    if !same_source(&account_source, &allowance.capacity) {
        return Err(invariant(
            "product reference counter changed after admission",
        ));
    }
    let additional = footprint.new_active_owners();
    if account
        .active()?
        .checked_add(additional)
        .is_none_or(|active| active > MAX_ACTIVE_REFERENCE_OWNERS)
    {
        return Err(invariant("reference tenant active quota exhausted"));
    }
    let before = global_head(tx)?;
    if !plan.staged_updates().is_empty() {
        crate::admission_operation_store::recovery::resources::check_intake_committing(tx)?;
    }
    for write in plan.staged_updates() {
        persist_update(tx, owner, write, ORDINARY_REFERENCE_BYTES)?;
    }
    let mut mutations = u64::try_from(footprint.record_count())
        .map_err(|_| invariant("reference mutation count overflow"))?;
    if additional != 0 {
        account.admitted = account
            .admitted
            .checked_add(additional)
            .ok_or_else(|| invariant("reference admitted counter exhausted"))?;
        account.batches = account
            .batches
            .checked_add(1)
            .ok_or_else(|| invariant("reference batch counter exhausted"))?;
        let (_, account_bytes) =
            save_capacity(tx, owner, plan.scope(), &account, Some(&account_source))?;
        bytes = bytes
            .checked_add(account_bytes)
            .ok_or_else(|| invariant("reference encoded byte count overflow"))?;
        mutations = mutations
            .checked_add(1)
            .ok_or_else(|| invariant("reference mutation count overflow"))?;
    }
    let after = global_head(tx)?;
    if before.sequence.checked_add(mutations) != Some(after.sequence) {
        return Err(invariant(
            "reference progress contains an unaccounted protected mutation",
        ));
    }
    Ok(ProtectedMutationDelta {
        mutations,
        encoded_bytes: bytes,
    })
}

pub(super) fn ordinary_slot(
    write: &StagedReferenceUpdate,
    references: &[ArtifactVersionRefV1],
    owner: &ReferenceOwner,
) -> Result<(usize, u8), AdmissionOperationStoreError> {
    if write.key().len() > 512
        || write.payload().is_empty()
        || write.payload().len() > ORDINARY_REFERENCE_BYTES
    {
        return Err(invariant(
            "ordinary reference row exceeds its accepted envelope",
        ));
    }
    for (index, reference) in references.iter().enumerate() {
        let identity = reference_identity(reference)?;
        let digest = hex::encode(identity.as_bytes());
        // All index headers follow the full target artifact scope. The actual
        // source and owner may use another process under the same account.
        if write.scope() != scope_key(&reference.scope)? {
            continue;
        }
        if write.key() == aggregate_key(identity) {
            return Ok((index, 0));
        }
        let leaf = format!(
            "knowledge-reference-owner:{digest}:{}",
            hex::encode(owner.identity(identity)?.as_bytes())
        );
        if write.key() == leaf {
            return Ok((index, 1));
        }
        let bucket_prefix = format!("knowledge-reference-bucket:{digest}:");
        if let Some(number) = write.key().strip_prefix(&bucket_prefix) {
            let ordinal = number
                .parse::<u64>()
                .map_err(|_| invariant("reference bucket ordinal is invalid"))?;
            SafeInteger::new(ordinal)
                .map_err(|_| invariant("reference bucket ordinal exhausted"))?;
            if ordinal != 0 && number == ordinal.to_string() {
                return Ok((index, 2));
            }
        }
    }
    Err(invariant(
        "reference plan exceeded its exact owner and target slots",
    ))
}
