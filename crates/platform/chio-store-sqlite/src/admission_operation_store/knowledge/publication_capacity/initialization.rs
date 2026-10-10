//! Publications start with no owners only in a verified new native account.
use super::super::account::{require_unused_key, NewKnowledgeAccount};
use super::*;

pub(in crate::admission_operation_store::knowledge) fn initialize_account(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    proof: &NewKnowledgeAccount<'_, '_>,
) -> Result<(), AdmissionOperationStoreError> {
    proof.verify(tx)?;
    let identity = account(proof.scope());
    let counter = capacity_key(&identity)?;
    let ready = ready_key(&identity)?;
    require_unused_key(tx, &counter)?;
    require_unused_key(tx, &ready)?;
    let baseline = CapacityBaseline {
        cutoff: proof.cutoff().clone(),
    };
    let capacity = CapacityRecord {
        schema: CapacitySchema::V1,
        account: identity.clone(),
        baseline: baseline.clone(),
        admitted: 0,
        collected: 0,
        changes: 0,
    };
    capacity.validate(1)?;
    let source = persist(tx, owner, &identity, &counter, &capacity, ACCOUNT_BYTES)?;
    persist(
        tx,
        owner,
        &identity,
        &ready,
        &ReadyRecord {
            schema: ReadySchema::V1,
            account: identity.clone(),
            baseline,
            capacity: SourceAnchor::capture(&source),
        },
        ACCOUNT_BYTES,
    )?;
    current_capacity(tx, proof.scope()).map(|_| ())
}
