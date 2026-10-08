//! Historical membership stays separate from permission to advance an owner.
use super::*;

pub(super) fn initial_head(
    claim: &SourceVersion,
    record: &OwnerDescriptor,
    scope: &RecoveryScopeV1,
) -> Result<OwnerHead, AdmissionOperationStoreError> {
    Ok(OwnerHead {
        schema: HeadSchema::V1,
        scope: scope.clone(),
        original_claim: claim.clone(),
        initial_owner: record.clone(),
        owner_ordinal: safe(1)?,
        current_owner: record.clone(),
        last_transfer: None,
    })
}

fn verify_descriptor(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    owner: &OwnerDescriptor,
) -> Result<RecoveryWorkflowRecordV1, AdmissionOperationStoreError> {
    let record = workflow_tx(tx, scope, &owner.workflow_id)?;
    if descriptor(tx, &record)? != *owner {
        return Err(invariant(
            "original owner descriptor changed its physical identity",
        ));
    }
    Ok(record)
}

fn verify_head_preimage(
    tx: &Connection,
    origin: &RecoveryOriginV1,
    head: &OwnerHead,
    source: &SourceVersion,
) -> Result<(), AdmissionOperationStoreError> {
    source.historical(tx, &head_key(origin)?)?;
    if source.version != head.owner_ordinal
        || record_digest(
            &head_key(origin)?,
            &scope_key(&head.scope)?,
            "command",
            source.version.get(),
            &encode(head)?,
            None,
            None,
        )? != hex(source.digest.as_bytes())
    {
        return Err(invariant(
            "original owner head lost its historical preimage",
        ));
    }
    Ok(())
}

fn transfer_reference(
    tx: &Connection,
    origin: &RecoveryOriginV1,
    ordinal: u64,
    scope: &RecoveryScopeV1,
) -> Result<SourceVersion, AdmissionOperationStoreError> {
    let (_, source): (OwnerTransfer, _) =
        checked_body(tx, &transfer_key(origin, ordinal)?, scope, true)?;
    Ok(source)
}

fn verify_transfer(
    tx: &Connection,
    origin: &RecoveryOriginV1,
    first: &OwnerHead,
    ordinal: u64,
) -> Result<(OwnerTransfer, SourceVersion), AdmissionOperationStoreError> {
    let (transfer, source): (OwnerTransfer, _) =
        checked_body(tx, &transfer_key(origin, ordinal)?, &first.scope, true)?;
    let previous = transfer.previous_owner_ordinal.get();
    if ordinal <= 1
        || previous.checked_add(1) != Some(ordinal)
        || transfer.successor_owner_ordinal.get() != ordinal
        || transfer.scope != first.scope
        || transfer.original_claim != first.original_claim
        || transfer.previous_head.version.get() != previous
        || transfer.previous_owner.workflow_id == transfer.successor.workflow_id
        || transfer.previous_owner.created_by != transfer.successor.created_by
    {
        return Err(invariant(
            "original transfer changed its exclusive succession",
        ));
    }
    let prior_record = verify_descriptor(tx, &first.scope, &transfer.previous_owner)?;
    verify_descriptor(tx, &first.scope, &transfer.successor)?;
    let prior = OwnerHead {
        owner_ordinal: transfer.previous_owner_ordinal,
        current_owner: transfer.previous_owner.clone(),
        last_transfer: if previous == 1 {
            None
        } else {
            Some(transfer_reference(tx, origin, previous, &first.scope)?)
        },
        ..first.clone()
    };
    verify_head_preimage(tx, origin, &prior, &transfer.previous_head)?;
    let closure_key = closure_key(&first.scope, &prior_record.workflow_id)?;
    let (closure, closure_source): (OwnerClosure, _) =
        checked_body(tx, &closure_key, &first.scope, true)?;
    if closure_source != transfer.closure
        || closure.scope != first.scope
        || closure.workflow_id != prior_record.workflow_id
        || closure.original != *origin
        || closure.original_claim != first.original_claim
        || closure.original_head != transfer.previous_head
        || closure.owner_ordinal != transfer.previous_owner_ordinal
        || transfer.previous_head.global_commit_sequence.get()
            >= closure_source.global_commit_sequence.get()
        || closure_source.global_commit_sequence.get()
            >= transfer.successor.initial.global_commit_sequence.get()
        || transfer.successor.initial.global_commit_sequence.get()
            >= source.global_commit_sequence.get()
    {
        return Err(invariant(
            "original transfer lost its exact closed predecessor",
        ));
    }
    no_future_admission::verify_retained_closure(tx, &prior_record, &closure)?;
    Ok((transfer, source))
}

pub(super) fn load_head(
    tx: &Connection,
    origin: &RecoveryOriginV1,
) -> Result<(OwnerHead, SourceVersion), AdmissionOperationStoreError> {
    let (claim, claim_source) = origins::load_immutable_claim(tx, origin)?;
    let first_record = workflow_tx(tx, &claim.scope, &claim.workflow_id)?;
    let expected_first = initial_head(
        &SourceVersion::capture(&claim_source)?,
        &descriptor(tx, &first_record)?,
        &claim.scope,
    )?;
    let (head, source): (OwnerHead, _) = checked_body(tx, &head_key(origin)?, &claim.scope, false)?;
    if claim.origin != *origin
        || first_record.origin.as_ref() != Some(origin)
        || first_record.continuation_id != claim.continuation_id
        || head.scope != claim.scope
        || head.original_claim != expected_first.original_claim
        || head.initial_owner != expected_first.initial_owner
        || source.version != head.owner_ordinal
        || head.owner_ordinal.get() == 0
    {
        return Err(invariant(
            "original owner head changed its permanent first owner",
        ));
    }
    let first_source = SourceVersion {
        version: safe(1)?,
        digest: ProjectionDigest::from_bytes(native::decode_hex(&historical_record_reference(tx, &head_key(origin)?, 1)?.0)?),
        event_sequence: safe(stored_u64(tx.query_row(
            "SELECT sequence FROM admission_operation_recovery_events WHERE record_key=?1 AND record_version=1", [&head_key(origin)?], |row| row.get(0),
        ).map_err(sqlite_error)?, "original first head event")?)?,
        global_commit_sequence: safe(historical_record_commit(tx, &head_key(origin)?, 1)?)?,
    };
    verify_head_preimage(tx, origin, &expected_first, &first_source)?;
    if head.owner_ordinal.get() == 1 {
        if head != expected_first {
            return Err(invariant("original first owner head changed"));
        }
    } else {
        let (transfer, transfer_source) =
            verify_transfer(tx, origin, &expected_first, head.owner_ordinal.get())?;
        if head.current_owner != transfer.successor
            || head.last_transfer.as_ref() != Some(&transfer_source)
            || transfer_source.global_commit_sequence.get() >= source.global_commit_sequence.get()
        {
            return Err(invariant("original current head lost its exact transfer"));
        }
    }
    verify_descriptor(tx, &head.scope, &head.current_owner)?;
    Ok((head, source))
}

pub(in crate::admission_operation_store) fn original_owner_is_current(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
) -> Result<bool, AdmissionOperationStoreError> {
    let Some(origin) = record.origin.as_ref() else {
        return Ok(false);
    };
    if !using_original_owner_successor_format(tx)? {
        let (claim, _) = origins::load_immutable_claim(tx, origin)?;
        descriptor(tx, record)?;
        return Ok(claim.scope == record.scope
            && claim.workflow_id == record.workflow_id
            && claim.continuation_id == record.continuation_id
            && claim.origin == *origin);
    }
    let (head, _) = load_head(tx, origin)?;
    if head.scope != record.scope || head.current_owner != descriptor(tx, record)? {
        return Ok(false);
    }
    Ok(
        raw_checked(tx, &closure_key(&record.scope, &record.workflow_id)?)?.is_none()
            && !unused_setup_generation::retired(tx, record)?,
    )
}

pub(super) fn verify_historical_owner(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
    source: &SourceVersion,
) -> Result<(), AdmissionOperationStoreError> {
    let origin = record
        .origin
        .as_ref()
        .ok_or_else(|| invariant("historical original owner lost provenance"))?;
    let (head, _) = load_head(tx, origin)?;
    if head.scope != record.scope
        || source.version.get() == 0
        || source.version.get() > head.owner_ordinal.get()
    {
        return Err(invariant(
            "historical original owner changed scope or ordinal",
        ));
    }
    let old = OwnerHead {
        owner_ordinal: source.version,
        current_owner: descriptor(tx, record)?,
        last_transfer: if source.version.get() == 1 {
            None
        } else {
            Some(transfer_reference(
                tx,
                origin,
                source.version.get(),
                &record.scope,
            )?)
        },
        ..head
    };
    verify_head_preimage(tx, origin, &old, source)
}

pub(in crate::admission_operation_store) fn require_current_original_owner(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    if !original_owner_is_current(tx, record)? {
        return Err(invariant("recovery original owner is closed or superseded"));
    }
    Ok(())
}

pub(in crate::admission_operation_store) fn verify_original_owner_membership(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    require_format(tx)?;
    let origin = record
        .origin
        .as_ref()
        .ok_or_else(|| invariant("original membership has no provenance"))?;
    let (head, _) = load_head(tx, origin)?;
    let actual = descriptor(tx, record)?;
    if head.scope != record.scope {
        return Err(invariant("original membership changed full scope"));
    }
    if actual == head.initial_owner {
        return Ok(());
    }
    let key: Option<String> = tx.query_row(
        "SELECT record_key FROM admission_operation_recovery_records
         WHERE kind='command' AND record_key GLOB 'recovery-original-transfer:*'
           AND scope_key=?1 AND json_extract(CAST(payload AS TEXT),'$.successor.workflow_id')=?2 LIMIT 1",
        params![scope_key(&record.scope)?, record.workflow_id.as_str()], |row| row.get(0),
    ).optional().map_err(sqlite_error)?;
    let key = key.ok_or_else(|| invariant("original successor lost its immutable membership"))?;
    let (transfer, _): (OwnerTransfer, _) = checked_body(tx, &key, &record.scope, true)?;
    if key != transfer_key(origin, transfer.successor_owner_ordinal.get())?
        || transfer.successor != actual
    {
        return Err(invariant(
            "original membership changed its accepted successor",
        ));
    }
    verify_transfer(tx, origin, &head, transfer.successor_owner_ordinal.get())?;
    Ok(())
}

#[derive(Eq, PartialEq)]
struct CohortCensus {
    sources: u64,
    digest: CanonicalPayloadDigest,
    encoded_bytes: u64,
}

fn visit_originals(
    tx: &Connection,
    owner: &SqliteServingOwner,
    mut visit: impl FnMut(&RecoveryOriginV1, &OwnerHead) -> Result<(), AdmissionOperationStoreError>,
) -> Result<CohortCensus, AdmissionOperationStoreError> {
    let mut result = CohortCensus {
        sources: 0,
        digest: CanonicalPayloadDigest::from_bytes([0; 32]),
        encoded_bytes: 0,
    };
    let mut query = tx.prepare(
        "SELECT record_key FROM admission_operation_recovery_records WHERE record_key GLOB 'recovery-origin:*'
         UNION SELECT record_key FROM admission_operation_recovery_events WHERE record_key GLOB 'recovery-origin:*'
         UNION SELECT projection_key FROM authority_global_commits WHERE projection_kind='recovery' AND projection_key GLOB 'recovery-origin:*' ORDER BY 1",
    ).map_err(sqlite_error)?;
    for key in query
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?
    {
        let key = key.map_err(sqlite_error)?;
        let (claim, source) = origins::load_claim_by_key(tx, &key)?;
        if claim.scope.authority_domain.as_str() != owner.fence.store_uuid {
            return Err(invariant("original cohort contains a foreign authority"));
        }
        let record = workflow_tx(tx, &claim.scope, &claim.workflow_id)?;
        if record.origin.as_ref() != Some(&claim.origin)
            || record.continuation_id != claim.continuation_id
        {
            return Err(invariant(
                "original cohort lost its immutable first workflow",
            ));
        }
        let physical = SourceVersion::capture(&source_reference(
            tx,
            &workflow_key(&record.scope, &record.workflow_id)?,
        )?)?;
        let claim_source = SourceVersion::capture(&source)?;
        let head = initial_head(&claim_source, &descriptor(tx, &record)?, &record.scope)?;
        let payload = encode(&head)?;
        if payload.len() > MAX_OWNER_BYTES {
            return Err(invariant("original cold head exceeds its closed envelope"));
        }
        result.sources = result
            .sources
            .checked_add(1)
            .ok_or_else(|| invariant("original cold census exhausted"))?;
        result.encoded_bytes = result
            .encoded_bytes
            .checked_add(
                u64::try_from(payload.len())
                    .map_err(|_| invariant("original cold bytes exhausted"))?,
            )
            .ok_or_else(|| invariant("original cold bytes exhausted"))?;
        result.digest = CanonicalPayloadDigest::from_bytes(
            *chio_core::sha256(&encode(&(
                RecoveryDigestDomain::ParticipantOwner.name(),
                "original_owner_cohort",
                result.digest,
                &key,
                claim_source,
                physical,
            ))?)
            .as_bytes(),
        );
        visit(&claim.origin, &head)?;
    }
    Ok(result)
}

/// Complete authenticated source census. Counts describe a cold plan and grant
/// neither physical capacity nor permission to publish a serving owner.
pub(in crate::admission_operation_store) struct VerifiedOriginalOwnerCohort<'owner, 'tx, 'conn> {
    tx: &'tx Transaction<'conn>,
    owner: &'owner SqliteServingOwner,
    cut: NativeSourceTransactionOrigin<'owner>,
    census: CohortCensus,
}

pub(in crate::admission_operation_store) fn prepare_original_owner_cohort<'owner, 'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    owner: &'owner SqliteServingOwner,
    cut: &NativeSourceTransactionOrigin<'owner>,
) -> Result<VerifiedOriginalOwnerCohort<'owner, 'tx, 'conn>, AdmissionOperationStoreError> {
    let stamp: i32 = tx
        .query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key=?1",
            [ADMISSION_OPERATION_SCHEMA_KEY],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if stamp > 40
        || global_sequence(tx)? != cut.prepared_global_sequence()
        || !cut.matches_owner(owner)
    {
        return Err(invariant(
            "original predecessor census did not precede successor mutations",
        ));
    }
    require_predecessor_original_owner_absence(tx)?;
    schema::verify_active_owner(tx, owner, Some(&owner.fence))?;
    cut.verify(tx).map_err(map_owner_error)?;
    crate::serving_owner::verify_authenticated_recovery_history(tx).map_err(map_owner_error)?;
    let census = visit_originals(tx, owner, |_, _| Ok(()))?;
    Ok(VerifiedOriginalOwnerCohort {
        tx,
        owner,
        cut: cut.fork_for_source(),
        census,
    })
}

impl VerifiedOriginalOwnerCohort<'_, '_, '_> {
    pub(in crate::admission_operation_store) fn planned_mutations(&self) -> u64 {
        self.census.sources
    }
    pub(in crate::admission_operation_store) fn encoded_bytes(&self) -> u64 {
        self.census.encoded_bytes
    }
}

pub(in crate::admission_operation_store) struct VerifiedOriginalOwnerInventory<'owner, 'tx, 'conn> {
    tx: &'tx Transaction<'conn>,
    owner: &'owner SqliteServingOwner,
    cut: NativeSourceTransactionOrigin<'owner>,
    census: CohortCensus,
    delta: ProtectedMutationDelta,
}

impl VerifiedOriginalOwnerInventory<'_, '_, '_> {
    pub(in crate::admission_operation_store) fn delta(&self) -> &ProtectedMutationDelta {
        &self.delta
    }
    pub(in crate::admission_operation_store) fn verify_before_stamp(
        &self,
        tx: &Transaction<'_>,
    ) -> Result<(), AdmissionOperationStoreError> {
        let stamp: i32 = tx
            .query_row(
                "SELECT version FROM chio_store_schema_versions WHERE store_key=?1",
                [ADMISSION_OPERATION_SCHEMA_KEY],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if stamp > 40
            || !std::ptr::eq::<Connection>(&**self.tx, &**tx)
            || !self.cut.matches_owner(self.owner)
        {
            return Err(invariant(
                "original completed inventory left its predecessor transaction",
            ));
        }
        self.cut.verify(tx).map_err(map_owner_error)?;
        let actual = visit_originals(tx, self.owner, |origin, expected| {
            let (head, _) = load_head(tx, origin)?;
            if head != *expected {
                return Err(invariant(
                    "original cohort lost its complete first-head inventory",
                ));
            }
            Ok(())
        })?;
        if actual != self.census {
            return Err(invariant(
                "original inventory changed its authenticated source census",
            ));
        }
        verify_inventory_contents(tx)
    }
}

pub(in crate::admission_operation_store) fn persist_original_owner_cohort<'owner, 'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    proof: VerifiedOriginalOwnerCohort<'owner, 'tx, 'conn>,
) -> Result<VerifiedOriginalOwnerInventory<'owner, 'tx, 'conn>, AdmissionOperationStoreError> {
    if !std::ptr::eq::<Connection>(&**proof.tx, &**tx) || !proof.cut.matches_owner(proof.owner) {
        return Err(invariant(
            "original cold writer changed its actual owner or transaction",
        ));
    }
    proof.cut.verify(tx).map_err(map_owner_error)?;
    let current = visit_originals(tx, proof.owner, |origin, _| {
        if raw_checked(tx, &head_key(origin)?)?.is_some() {
            return Err(invariant("original cold cohort is partially installed"));
        }
        Ok(())
    })?;
    if current != proof.census {
        return Err(invariant(
            "original cold sources changed before first head write",
        ));
    }
    super::super::super::resources::check_intake_committing(tx)?;
    let before = global_sequence(tx)?;
    let mut delta = ProtectedMutationDelta::zero();
    visit_originals(tx, proof.owner, |origin, head| {
        let (_, written) = persist(
            tx,
            proof.owner,
            &proof.cut,
            &head_key(origin)?,
            &head.scope,
            head,
        )?;
        delta = delta.checked_add(&written)?;
        Ok(())
    })?;
    if delta.mutations() != proof.census.sources
        || delta.encoded_bytes() != proof.census.encoded_bytes
        || global_sequence(tx)?
            != before
                .checked_add(delta.mutations())
                .ok_or_else(|| invariant("original cold global count exhausted"))?
    {
        return Err(invariant(
            "original cold writer omitted its complete actual footprint",
        ));
    }
    let inventory = VerifiedOriginalOwnerInventory {
        tx,
        owner: proof.owner,
        cut: proof.cut,
        census: proof.census,
        delta,
    };
    inventory.verify_before_stamp(tx)?;
    super::super::super::resources::check_intake_committing(tx)?;
    Ok(inventory)
}

pub(in crate::admission_operation_store) fn verify_original_owner_inventory(
    tx: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let stamp: Option<i32> = tx
        .query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key=?1",
            [ADMISSION_OPERATION_SCHEMA_KEY],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if stamp.is_some_and(|version| version <= 40) {
        return require_predecessor_original_owner_absence(tx);
    }
    require_format(tx)?;
    verify_inventory_contents(tx)
}

fn verify_inventory_contents(tx: &Connection) -> Result<(), AdmissionOperationStoreError> {
    let mut claims = tx.prepare(
        "SELECT record_key FROM admission_operation_recovery_records WHERE record_key GLOB 'recovery-origin:*'
         UNION SELECT record_key FROM admission_operation_recovery_events WHERE record_key GLOB 'recovery-origin:*'
         UNION SELECT projection_key FROM authority_global_commits WHERE projection_kind='recovery' AND projection_key GLOB 'recovery-origin:*' ORDER BY 1",
    ).map_err(sqlite_error)?;
    for key in claims
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?
    {
        let (claim, _) = origins::load_claim_by_key(tx, &key.map_err(sqlite_error)?)?;
        load_head(tx, &claim.origin)?;
    }
    let mut records = tx.prepare(
        "SELECT record_key FROM admission_operation_recovery_records WHERE record_key GLOB 'recovery-original-*'
         UNION SELECT record_key FROM admission_operation_recovery_events WHERE record_key GLOB 'recovery-original-*'
         UNION SELECT projection_key FROM authority_global_commits WHERE projection_kind='recovery' AND projection_key GLOB 'recovery-original-*' ORDER BY 1",
    ).map_err(sqlite_error)?;
    for key in records
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?
    {
        let key = key.map_err(sqlite_error)?;
        let row = raw_checked(tx, &key)?
            .ok_or_else(|| invariant("original inventory lost its physical metadata"))?;
        if key.starts_with("recovery-original-owner:") {
            let body: OwnerHead = decode(&row.payload)?;
            let record = workflow_tx(tx, &body.scope, &body.initial_owner.workflow_id)?;
            let origin = record
                .origin
                .as_ref()
                .ok_or_else(|| invariant("original head lost its provenance"))?;
            if key != head_key(origin)? {
                return Err(invariant("original head key changed"));
            }
            load_head(tx, origin)?;
        } else if key.starts_with("recovery-original-transfer:") {
            let body: OwnerTransfer = decode(&row.payload)?;
            let record = workflow_tx(tx, &body.scope, &body.successor.workflow_id)?;
            let origin = record
                .origin
                .as_ref()
                .ok_or_else(|| invariant("original transfer lost its successor provenance"))?;
            let (head, _) = load_head(tx, origin)?;
            if key != transfer_key(origin, body.successor_owner_ordinal.get())? {
                return Err(invariant("original transfer changed its inverse key"));
            }
            verify_transfer(tx, origin, &head, body.successor_owner_ordinal.get())?;
        } else if key.starts_with("recovery-original-tombstone:") {
            let body: OwnerClosure = decode(&row.payload)?;
            let record = workflow_tx(tx, &body.scope, &body.workflow_id)?;
            if key != closure_key(&body.scope, &body.workflow_id)? {
                return Err(invariant("original closure key changed"));
            }
            let (_, _): (OwnerClosure, _) = checked_body(tx, &key, &body.scope, true)?;
            no_future_admission::verify_retained_closure(tx, &record, &body)?;
            let (head, _) = load_head(tx, &body.original)?;
            let ordinal = body
                .owner_ordinal
                .get()
                .checked_add(1)
                .ok_or_else(|| invariant("original closure succession exhausted"))?;
            let (transfer, _) = verify_transfer(tx, &body.original, &head, ordinal)?;
            if transfer.closure != SourceVersion::capture(&source_reference(tx, &key)?)? {
                return Err(invariant(
                    "original closure has no accepted unique successor",
                ));
            }
        } else {
            return Err(invariant("original inventory has unknown metadata"));
        }
    }
    Ok(())
}
