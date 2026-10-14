//! One current owner per original, with immutable transfer bindings.
//!
//! Before the first transfer the origin claim is the current owner. A transfer
//! atomically advances the optional owner head and records its exact pre- and
//! post-images in retained history. Missing projections with retained history
//! refuse. Each generation proves membership directly, without a chain walk.
use super::*;
use chio_security_types::flow::PrincipalId;
use serde::{Deserialize, Serialize};

const MAX_BINDING_BYTES: usize = 4096;
const MAX_HEAD_BYTES: usize = 4096;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SuccessorBinding {
    schema: SuccessorBindingSchema,
    scope: RecoveryScopeV1,
    origin: RecoveryOriginV1,
    principal: PrincipalId,
    predecessor_workflow_id: WorkflowId,
    predecessor_continuation_id: ContinuationId,
    predecessor_generation: SafeInteger,
    successor_workflow_id: WorkflowId,
    successor_continuation_id: ContinuationId,
    successor_generation: SafeInteger,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
enum SuccessorBindingSchema {
    #[serde(rename = "chio.recovery.successor-binding.v1")]
    V1,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerHead {
    schema: OwnerHeadSchema,
    scope: RecoveryScopeV1,
    origin: RecoveryOriginV1,
    principal: PrincipalId,
    current_owner: WorkflowId,
    current_continuation_id: ContinuationId,
    current_generation: SafeInteger,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
enum OwnerHeadSchema {
    #[serde(rename = "chio.recovery.owner-head.v1")]
    V1,
}

/// The head is keyed by the immutable claim identity, never workflow state.
pub(in crate::admission_operation_store::recovery) fn owner_head_key(
    scope: &RecoveryScopeV1,
    origin: &RecoveryOriginV1,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "recovery-owner:{}:{}",
        scope_key(scope)?,
        super::super::origins::origin_hash(origin)?
    ))
}

/// Bindings are keyed by their successor generation, so membership checks
/// stay constant-size with no chain traversal.
fn binding_key(
    scope: &RecoveryScopeV1,
    successor: &WorkflowId,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "recovery-successor:{}:{}",
        scope_key(scope)?,
        successor.as_str()
    ))
}

fn decode_binding(payload: &[u8]) -> Result<SuccessorBinding, AdmissionOperationStoreError> {
    if payload.is_empty() || payload.len() > MAX_BINDING_BYTES {
        return Err(invariant("recovery successor binding exceeds its bound"));
    }
    let binding: SuccessorBinding = decode(payload)?;
    if binding.schema != SuccessorBindingSchema::V1
        || binding.predecessor_generation.get() == 0
        || binding.successor_generation.get() != binding.predecessor_generation.get() + 1
    {
        return Err(invariant("recovery successor binding schema refused"));
    }
    Ok(binding)
}

fn decode_head(payload: &[u8]) -> Result<OwnerHead, AdmissionOperationStoreError> {
    if payload.is_empty() || payload.len() > MAX_HEAD_BYTES {
        return Err(invariant("recovery owner head exceeds its bound"));
    }
    let head: OwnerHead = decode(payload)?;
    if head.schema != OwnerHeadSchema::V1 || head.current_generation.get() == 0 {
        return Err(invariant("recovery owner head schema refused"));
    }
    Ok(head)
}

fn load_binding(
    tx: &Connection,
    key: &str,
) -> Result<Option<SuccessorBinding>, AdmissionOperationStoreError> {
    let Some(row) = raw_checked(tx, key)? else {
        return Ok(None);
    };
    let binding = decode_binding(&row.payload)?;
    if row.kind != "command"
        || row.version != 1
        || row.scope != scope_key(&binding.scope)?
        || key != binding_key(&binding.scope, &binding.successor_workflow_id)?
        || source_reference(tx, key)?.version() != 1
    {
        return Err(invariant("recovery successor binding changed its source"));
    }
    Ok(Some(binding))
}

/// The exact head image for one generation of this claim, with its canonical
/// payload. Version one is the closed first claim owner; a later version is
/// the bound successor of the previous one.
fn head_image(
    claim: &super::super::origins::OriginClaim,
    principal: &PrincipalId,
    owner: &WorkflowId,
    continuation: &ContinuationId,
    generation: u64,
) -> Result<(OwnerHead, Vec<u8>), AdmissionOperationStoreError> {
    let head = OwnerHead {
        schema: OwnerHeadSchema::V1,
        scope: claim.scope.clone(),
        origin: claim.origin.clone(),
        principal: principal.clone(),
        current_owner: owner.clone(),
        current_continuation_id: continuation.clone(),
        current_generation: SafeInteger::new(generation)
            .map_err(|_| invariant("recovery owner generation refused"))?,
    };
    let payload = encode(&head)?;
    if payload.len() > MAX_HEAD_BYTES {
        return Err(invariant("recovery owner head exceeds its bound"));
    }
    Ok((head, payload))
}

/// Owner head key and canonical bytes for one generation, for writer-level regressions.
#[cfg(test)]
pub(in crate::admission_operation_store) fn owner_head_record_for_test(
    scope: &RecoveryScopeV1,
    origin: &RecoveryOriginV1,
    principal: &PrincipalId,
    owner: &WorkflowId,
    continuation: &ContinuationId,
    generation: u64,
) -> Result<(String, Vec<u8>), AdmissionOperationStoreError> {
    let claim = super::super::origins::OriginClaim {
        scope: scope.clone(),
        workflow_id: owner.clone(),
        continuation_id: continuation.clone(),
        origin: origin.clone(),
    };
    let (_, payload) = head_image(&claim, principal, owner, continuation, generation)?;
    Ok((owner_head_key(scope, origin)?, payload))
}

/// The retained head row for a claim, if its projection exists. The row's
/// current body and its exact source binding are revalidated together.
fn read_head(
    tx: &Connection,
    claim: &super::super::origins::OriginClaim,
) -> Result<Option<OwnerHead>, AdmissionOperationStoreError> {
    let key = owner_head_key(&claim.scope, &claim.origin)?;
    let Some(row) = raw_checked(tx, &key)? else {
        return Ok(None);
    };
    if row.kind != "command"
        || row.scope != scope_key(&claim.scope)?
        || row.payload.len() > MAX_HEAD_BYTES
    {
        return Err(invariant("recovery original owner head is corrupt"));
    }
    let source = source_reference(tx, &key)?;
    if source.version() != row.version {
        return Err(invariant("recovery original owner head lost its source"));
    }
    let head = decode_head(&row.payload)?;
    if head.scope != claim.scope
        || head.origin != claim.origin
        || head.current_generation.get() != row.version
        // A committed head always advanced past its opening first image
        // inside the first transfer writer, so a persisted generation one
        // row is an incomplete or forged projection, never current state.
        || head.current_generation.get() < 2
    {
        return Err(invariant("recovery original owner head changed its owner"));
    }
    Ok(Some(head))
}

/// Admission intent is write-once and precedes native begin. Its absence,
/// together with the retired allocation and closed admission, proves that this
/// cancelled generation has no dispatch or Process debt to transfer.
fn require_predecessor_closure(
    tx: &Connection,
    predecessor: &RecoveryWorkflowRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    if predecessor.control != WorkflowControlV1::Cancelled
        || !predecessor.admission_closed
        || predecessor.admission.is_some()
        || predecessor.captured
        || predecessor.native_link.is_some()
        || predecessor.process_reservation.is_some()
        || predecessor.historical_hold.is_some()
        || auxiliary_historical_hold(tx, predecessor)?.is_some()
        || predecessor.effect != EffectObservationV1::NeverAdmitted
        || predecessor.release != ReleaseDispositionV1::NotAvailable
        || predecessor.provider_finality.is_some()
        || predecessor.reported_decision.is_some()
        || predecessor.provider_lookups.get() != 0
        || !super::active_workflows::retirement_committed(
            tx,
            &predecessor.scope,
            &predecessor.workflow_id,
        )?
    {
        return Err(invariant(
            "recovery predecessor lacks its verified no-effect closure",
        ));
    }
    Ok(())
}

fn persist_head_image(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    claim: &super::super::origins::OriginClaim,
    principal: &PrincipalId,
    workflow: &WorkflowId,
    continuation: &ContinuationId,
    generation: u64,
) -> Result<(), RecoveryCommandPortError> {
    let (_, payload) = head_image(claim, principal, workflow, continuation, generation)?;
    save(
        tx,
        owner,
        &owner_head_key(&claim.scope, &claim.origin)?,
        &scope_key(&claim.scope)?,
        "command",
        &payload,
        None,
    )?;
    Ok(())
}

/// Advance the current owner and append its immutable binding in one writer.
/// The first transfer retains both the initial and successor head images;
/// later transfers advance the existing head. Prior generation rows stay fixed.
pub(in crate::admission_operation_store::recovery) fn transfer_to_successor(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    claim: &super::super::origins::OriginClaim,
    record: &RecoveryWorkflowRecordV1,
) -> Result<(), RecoveryCommandPortError> {
    if record.scope != claim.scope || record.origin.as_ref() != Some(&claim.origin) {
        return Err(RecoveryCommandPortError::Conflict);
    }
    let key = binding_key(&claim.scope, &record.workflow_id)?;
    if raw_checked(tx, &key)?.is_some() {
        return Err(RecoveryCommandPortError::Conflict);
    }
    let (predecessor, predecessor_generation) = match read_head(tx, claim)? {
        None => {
            // Pristine absence: the first claim owner is the closed first
            // generation, and its image opens the head projection.
            let first = workflow_tx(tx, &claim.scope, &claim.workflow_id)?;
            if first.created_by != record.created_by
                || first.continuation_id != claim.continuation_id
                || first.control != WorkflowControlV1::Cancelled
            {
                return Err(RecoveryCommandPortError::Conflict);
            }
            require_predecessor_closure(tx, &first)?;
            (first, 1_u64)
        }
        Some(head) => {
            let current = workflow_tx(tx, &claim.scope, &head.current_owner)?;
            if current.continuation_id != head.current_continuation_id
                || current.created_by != head.principal
                || current.created_by != record.created_by
                || current.origin.as_ref() != Some(&claim.origin)
                || current.control != WorkflowControlV1::Cancelled
            {
                return Err(RecoveryCommandPortError::Conflict);
            }
            require_predecessor_closure(tx, &current)?;
            (current, head.current_generation.get())
        }
    };
    let successor_generation = predecessor_generation
        .checked_add(1)
        .ok_or_else(|| invariant("recovery owner generation exhausted"))?;
    let binding = SuccessorBinding {
        schema: SuccessorBindingSchema::V1,
        scope: claim.scope.clone(),
        origin: claim.origin.clone(),
        principal: record.created_by.clone(),
        predecessor_workflow_id: predecessor.workflow_id.clone(),
        predecessor_continuation_id: predecessor.continuation_id.clone(),
        predecessor_generation: SafeInteger::new(predecessor_generation)
            .map_err(|_| invariant("recovery owner generation refused"))?,
        successor_workflow_id: record.workflow_id.clone(),
        successor_continuation_id: record.continuation_id.clone(),
        successor_generation: SafeInteger::new(successor_generation)
            .map_err(|_| invariant("recovery owner generation refused"))?,
    };
    let payload = encode(&binding)?;
    if payload.len() > MAX_BINDING_BYTES {
        return Err(invariant("recovery successor binding exceeds its bound").into());
    }
    if predecessor_generation == 1 {
        // The opening transfer first records the closed first claim owner.
        persist_head_image(
            tx,
            owner,
            claim,
            &record.created_by,
            &predecessor.workflow_id,
            &predecessor.continuation_id,
            1,
        )?;
    }
    save(
        tx,
        owner,
        &key,
        &scope_key(&claim.scope)?,
        "command",
        &payload,
        None,
    )?;
    persist_head_image(
        tx,
        owner,
        claim,
        &record.created_by,
        &record.workflow_id,
        &record.continuation_id,
        successor_generation,
    )?;
    if load_binding(tx, &key)?.as_ref() != Some(&binding) {
        return Err(invariant("recovery successor binding changed during its write").into());
    }
    let head =
        read_head(tx, claim)?.ok_or_else(|| invariant("recovery original owner head is absent"))?;
    if head.current_owner != record.workflow_id
        || head.current_continuation_id != record.continuation_id
        || head.current_generation.get() != successor_generation
    {
        return Err(invariant("recovery owner head changed during its write").into());
    }
    Ok(())
}

/// A replayed first-generation creation keeps its identity only while no
/// head projection exists: pristine absence means the first claim owner is
/// still current, and any committed head names a transferred successor, so
/// the first generation can no longer re-claim.
pub(in crate::admission_operation_store::recovery) fn verify_first_generation_current(
    tx: &Connection,
    claim: &super::super::origins::OriginClaim,
) -> Result<(), RecoveryCommandPortError> {
    match read_head(tx, claim)? {
        None => Ok(()),
        Some(_) => Err(RecoveryCommandPortError::Conflict),
    }
}

/// Whether this record is the claim's single current owner generation. With
/// a pristine head only the first claim owner is current; with a head only
/// its named generation is. Historical members are not current.
pub(in crate::admission_operation_store::recovery) fn verify_current_owner(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
    claim: &super::super::origins::OriginClaim,
) -> Result<bool, AdmissionOperationStoreError> {
    if record.scope != claim.scope || record.origin.as_ref() != Some(&claim.origin) {
        return Ok(false);
    }
    match read_head(tx, claim)? {
        None => Ok(claim.workflow_id == record.workflow_id
            && claim.continuation_id == record.continuation_id),
        Some(head) => Ok(head.principal == record.created_by
            && head.current_owner == record.workflow_id
            && head.current_continuation_id == record.continuation_id),
    }
}

/// Verify one binding's exact pre and post head images against their
/// retained event and global-commit references, its predecessor closure,
/// its successor identity and its claim. This is the complete historical
/// membership proof for one generation; it never walks a chain.
fn verify_binding_membership(
    tx: &Connection,
    key: &str,
    binding: &SuccessorBinding,
    claim: &super::super::origins::OriginClaim,
) -> Result<(), AdmissionOperationStoreError> {
    let head_key = owner_head_key(&claim.scope, &claim.origin)?;
    let scope_hash = scope_key(&claim.scope)?;
    let (pre_image, pre_payload) = head_image(
        claim,
        &binding.principal,
        &binding.predecessor_workflow_id,
        &binding.predecessor_continuation_id,
        binding.predecessor_generation.get(),
    )?;
    let (_, post_payload) = head_image(
        claim,
        &binding.principal,
        &binding.successor_workflow_id,
        &binding.successor_continuation_id,
        binding.successor_generation.get(),
    )?;
    if key != binding_key(&binding.scope, &binding.successor_workflow_id)?
        || binding.scope != claim.scope
        || binding.origin != claim.origin
    {
        return Err(invariant("recovery successor binding changed its claim"));
    }
    if binding.predecessor_generation.get() == 1 {
        // Head version one reconstructs the immutable first claim owner.
        if pre_image.current_owner != claim.workflow_id
            || pre_image.current_continuation_id != claim.continuation_id
        {
            return Err(invariant(
                "recovery first head image is not the claim owner",
            ));
        }
    } else {
        // A later predecessor must itself be a bound successor generation.
        let predecessor_key = binding_key(&claim.scope, &binding.predecessor_workflow_id)?;
        let predecessor_binding = load_binding(tx, &predecessor_key)?
            .ok_or_else(|| invariant("recovery successor binding lost its predecessor binding"))?;
        if predecessor_binding.scope != binding.scope
            || predecessor_binding.origin != binding.origin
            || predecessor_binding.successor_workflow_id != binding.predecessor_workflow_id
            || predecessor_binding.successor_continuation_id != binding.predecessor_continuation_id
            || predecessor_binding.successor_generation.get()
                != binding.predecessor_generation.get()
            || predecessor_binding.principal != binding.principal
        {
            return Err(invariant(
                "recovery successor binding chains outside its original",
            ));
        }
    }
    // The immutable transfer must lie between its exact pre- and post-images.
    let binding_commit = source_reference(tx, key)?.global_commit_sequence();
    for (version, image, before_binding) in [
        (binding.predecessor_generation.get(), &pre_payload, true),
        (binding.successor_generation.get(), &post_payload, false),
    ] {
        let (digest, commit) = historical_record_reference(tx, &head_key, version)?;
        if (before_binding && commit >= binding_commit)
            || (!before_binding && commit <= binding_commit)
            || digest
                != record_digest(
                    &head_key,
                    &scope_hash,
                    "command",
                    version,
                    image,
                    None,
                    None,
                )?
        {
            return Err(invariant("recovery owner head image changed its history"));
        }
    }
    let predecessor = workflow_tx(tx, &claim.scope, &binding.predecessor_workflow_id)?;
    if predecessor.continuation_id != binding.predecessor_continuation_id
        || predecessor.created_by != binding.principal
        || predecessor.origin.as_ref() != Some(&claim.origin)
    {
        return Err(invariant("recovery successor binding lost its predecessor"));
    }
    require_predecessor_closure(tx, &predecessor)?;
    let successor = workflow_tx(tx, &claim.scope, &binding.successor_workflow_id)?;
    if successor.continuation_id != binding.successor_continuation_id
        || successor.created_by != binding.principal
        || successor.origin.as_ref() != Some(&claim.origin)
    {
        return Err(invariant("recovery successor binding lost its successor"));
    }
    Ok(())
}

/// Whether this record is a bound historical generation of the claim: one
/// immutable binding names it as successor and passes the complete
/// membership proof. Constant-size reads only.
pub(in crate::admission_operation_store::recovery) fn verify_bound_generation(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
    claim: &super::super::origins::OriginClaim,
) -> Result<bool, AdmissionOperationStoreError> {
    let key = binding_key(&claim.scope, &record.workflow_id)?;
    let Some(binding) = load_binding(tx, &key)? else {
        return Ok(false);
    };
    if binding.successor_workflow_id != record.workflow_id
        || binding.successor_continuation_id != record.continuation_id
        || record.created_by != binding.principal
    {
        return Ok(false);
    }
    let head =
        read_head(tx, claim)?.ok_or_else(|| invariant("recovery original owner head is absent"))?;
    if binding.successor_generation.get() > head.current_generation.get() {
        return Ok(false);
    }
    verify_binding_membership(tx, &key, &binding, claim)?;
    Ok(true)
}

/// Planning inventory scope for a binding row. Public-typed result only.
pub(super) fn planning_binding_scope(
    key: &str,
    payload: &[u8],
) -> Result<RecoveryScopeV1, AdmissionOperationStoreError> {
    let binding = decode_binding(payload)?;
    if key != binding_key(&binding.scope, &binding.successor_workflow_id)? {
        return Err(invariant("recovery planning successor binding changed"));
    }
    Ok(binding.scope)
}

/// Planning inventory scope for a head row. Public-typed result only.
pub(super) fn planning_head_scope(
    key: &str,
    payload: &[u8],
) -> Result<RecoveryScopeV1, AdmissionOperationStoreError> {
    let head = decode_head(payload)?;
    if key != owner_head_key(&head.scope, &head.origin)? {
        return Err(invariant("recovery planning owner head changed"));
    }
    Ok(head.scope)
}

/// Planning inventory generation check for a head row.
pub(super) fn planning_head_generation(
    payload: &[u8],
) -> Result<u64, AdmissionOperationStoreError> {
    Ok(decode_head(payload)?.current_generation.get())
}

/// Streaming startup validation. Every binding passes its complete
/// membership proof and keeps its claim's committed head projection; every
/// retained head row keeps a valid claim, its current owner and its current
/// generation's own binding. No global row count cap or in-memory inventory
/// is used.
pub(super) fn verify_owner_inventory(tx: &Connection) -> Result<(), AdmissionOperationStoreError> {
    let mut bindings = tx
        .prepare(
            "SELECT record_key FROM main.admission_operation_recovery_records WHERE record_key GLOB 'recovery-successor:*' ORDER BY record_key",
        )
        .map_err(sqlite_error)?;
    let rows = bindings
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?;
    for key in rows {
        let key = key.map_err(sqlite_error)?;
        let binding = load_binding(tx, &key)?
            .ok_or_else(|| invariant("recovery successor binding is absent"))?;
        let (claim, _) = super::super::origins::load_claim_by_key(
            tx,
            &super::super::origins::claim_key(&binding.origin)?,
        )?;
        // A committed binding requires its committed head projection; a
        // lost, removed or un-advanced head is refused by the reader.
        let head = read_head(tx, &claim)?
            .ok_or_else(|| invariant("recovery successor binding lost its owner head"))?;
        if binding.successor_generation.get() > head.current_generation.get() {
            return Err(invariant(
                "recovery successor binding exceeds its owner head",
            ));
        }
        verify_binding_membership(tx, &key, &binding, &claim)?;
    }
    let mut heads = tx
        .prepare(
            "SELECT record_key FROM main.admission_operation_recovery_records WHERE record_key GLOB 'recovery-owner:*' ORDER BY record_key",
        )
        .map_err(sqlite_error)?;
    let head_rows = heads
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?;
    for key in head_rows {
        let key = key.map_err(sqlite_error)?;
        let row =
            raw_checked(tx, &key)?.ok_or_else(|| invariant("recovery owner head is absent"))?;
        let head = decode_head(&row.payload)?;
        if row.kind != "command"
            || row.scope != scope_key(&head.scope)?
            || key != owner_head_key(&head.scope, &head.origin)?
            || head.current_generation.get() != row.version
            // A committed head advanced past its opening first image inside
            // the first transfer, so a version-one row is an incomplete or
            // forged projection, never a current first generation.
            || head.current_generation.get() < 2
        {
            return Err(invariant("recovery owner head is corrupt"));
        }
        let source = source_reference(tx, &key)?;
        if source.version() != row.version {
            return Err(invariant("recovery owner head lost its source"));
        }
        let (claim, _) = super::super::origins::load_claim_by_key(
            tx,
            &super::super::origins::claim_key(&head.origin)?,
        )?;
        if claim.scope != head.scope || claim.origin != head.origin {
            return Err(invariant("recovery owner head changed its claim"));
        }
        let owner = workflow_tx(tx, &claim.scope, &head.current_owner)?;
        if owner.continuation_id != head.current_continuation_id
            || owner.created_by != head.principal
            || owner.origin.as_ref() != Some(&claim.origin)
        {
            return Err(invariant("recovery owner head lost its owner"));
        }
        // The current generation's own binding carries its exact post image.
        let binding = load_binding(tx, &binding_key(&claim.scope, &head.current_owner)?)?
            .ok_or_else(|| invariant("recovery owner head lost its binding"))?;
        if binding.successor_workflow_id != head.current_owner
            || binding.successor_continuation_id != head.current_continuation_id
            || binding.successor_generation.get() != head.current_generation.get()
            || binding.principal != head.principal
        {
            return Err(invariant("recovery owner head changed its binding"));
        }
        // The binding inventory above already verified both historical images.
    }
    Ok(())
}
