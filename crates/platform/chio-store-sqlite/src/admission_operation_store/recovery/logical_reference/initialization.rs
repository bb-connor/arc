//! One native account initialization precedes all reference intake.
use super::*;
use crate::admission_operation_store::knowledge::{
    account::require_unused_key,
    references::{PreparedNewArtifactReferenceBaseline, ReferenceReadySchema},
};

pub(in crate::admission_operation_store) fn initialize_knowledge_reference_account(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    proof: &NewKnowledgeAccount<'_, '_>,
) -> Result<(), AdmissionOperationStoreError> {
    require_reference_format(tx)?;
    crate::admission_operation_store::schema::verify_active_owner(tx, owner, Some(&owner.fence))?;
    proof.verify(tx)?;
    if proof.scope().authority_domain.as_str() != owner.fence.store_uuid {
        return Err(invariant(
            "reference initialization changed its native authority",
        ));
    }
    let account = ReferenceAccount::from_scope(proof.scope());
    let (capacity_key, _) = reference_capacity::identity(proof.scope())?;
    let key = account.ready_key()?;
    require_unused_key(tx, &capacity_key)?;
    require_unused_key(tx, &key)?;
    crate::admission_operation_store::recovery::resources::check_intake_committing(tx)?;
    let record = ReferenceReadyRecord {
        schema: ReferenceReadySchema::V3,
        account,
        cutoff: proof.cutoff().clone(),
    };
    save_capacity(
        tx,
        owner,
        proof.scope(),
        &ReferenceCapacity::new(proof),
        None,
    )?;
    let bytes = encode(&record)?;
    if bytes.len() > ACCOUNT_RECORD_BYTES {
        return Err(invariant("reference readiness exceeds its closed envelope"));
    }
    persist_record(
        tx,
        owner,
        &key,
        &record.account.scope_key()?,
        "command",
        &bytes,
        None,
    )?;
    verify_knowledge_reference_account(tx, proof.scope())
}

pub(in crate::admission_operation_store) fn verify_knowledge_reference_account(
    tx: &Connection,
    scope: &RecoveryScopeV1,
) -> Result<(), AdmissionOperationStoreError> {
    require_ready_capacity(tx, scope).map(|_| ())
}

/// The authenticated MetadataCommitted phase is still reversible. This fresh
/// logical initialization must finish before the publication becomes Available.
pub(in crate::admission_operation_store) fn persist_knowledge_new_artifact_reference_baseline<
    'tx,
    'conn,
>(
    tx: &'tx Transaction<'conn>,
    owner: &SqliteServingOwner,
    plan: PreparedNewArtifactReferenceBaseline<'tx, 'conn>,
) -> Result<(ProtectedSourceReference, ProtectedMutationDelta), AdmissionOperationStoreError> {
    require_reference_format(tx)?;
    same_writer(plan.transaction(), tx)?;
    crate::admission_operation_store::schema::verify_active_owner(tx, owner, Some(&owner.fence))?;
    plan.verify_current(tx)?;
    require_ready_capacity(tx, &plan.reference().scope)?;
    let write = plan.staged_update();
    if write.key() != aggregate_key(reference_identity(plan.reference())?)
        || write.scope() != scope_key(&plan.reference().scope)?
        || write.expected_version().is_some()
        || write.version() != 1
    {
        return Err(invariant(
            "new artifact baseline changed its exact zero initializer",
        ));
    }
    crate::admission_operation_store::recovery::resources::check_intake_committing(tx)?;
    let before = global_head(tx)?;
    let source = persist_update(tx, owner, write, ORDINARY_REFERENCE_BYTES)?;
    let after = global_head(tx)?;
    if before.sequence.checked_add(1) != Some(after.sequence)
        || source.global_commit_sequence() != after.sequence
    {
        return Err(invariant(
            "new artifact baseline changed its exact write footprint",
        ));
    }
    Ok((
        source,
        ProtectedMutationDelta {
            mutations: 1,
            encoded_bytes: u64::try_from(write.payload().len())
                .map_err(|_| invariant("reference baseline byte count overflow"))?,
        },
    ))
}
