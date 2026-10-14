//! Publications start with no owners only in a verified new native account.
use super::super::account::{require_unused_key, NewKnowledgeAccount};
use super::*;

pub(in crate::admission_operation_store::knowledge) fn initialize_account(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    proof: &NewKnowledgeAccount<'_, '_>,
) -> Result<(), AdmissionOperationStoreError> {
    protected::persist_knowledge_account_bootstrap(tx, owner, proof)?;
    current_capacity(tx, proof.scope()).map(|_| ())
}

/// The empty counter of a new account, then its ready record anchored to the
/// written counter. Both keys must have no retained custody.
pub(in crate::admission_operation_store) fn bootstrap_write(
    tx: &Connection,
    proof: &NewKnowledgeAccount<'_, '_>,
    counter: Option<&protected::ProtectedSourceReference>,
) -> Result<DerivedWrite, AdmissionOperationStoreError> {
    let identity = account(proof.scope());
    let baseline = CapacityBaseline {
        cutoff: proof.cutoff().clone(),
    };
    let scope_key = identity.scope_key()?;
    let Some(counter) = counter else {
        let key = capacity_key(&identity)?;
        require_unused_key(tx, &key)?;
        require_unused_key(tx, &ready_key(&identity)?)?;
        let capacity = CapacityRecord {
            schema: CapacitySchema::V1,
            account: identity,
            baseline,
            admitted: 0,
            collected: 0,
            changes: 0,
        };
        capacity.validate(1)?;
        return Ok(DerivedWrite {
            payload: bounded(&capacity, ACCOUNT_BYTES)?,
            key,
            scope_key,
            expected: None,
        });
    };
    let key = ready_key(&identity)?;
    if counter.record_key() != capacity_key(&identity)? || counter.version() != 1 {
        return Err(refused("knowledge account ready lost its counter"));
    }
    require_unused_key(tx, &key)?;
    Ok(DerivedWrite {
        payload: bounded(
            &ReadyRecord {
                schema: ReadySchema::V1,
                account: identity,
                baseline,
                capacity: SourceAnchor::capture(counter),
            },
            ACCOUNT_BYTES,
        )?,
        key,
        scope_key,
        expected: None,
    })
}
