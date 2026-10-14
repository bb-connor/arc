//! Reopen checks compare current accounting against retained native ownership.
use super::*;

/// Catalog validation checks both directions. Protected lease absence and orphan
/// lease/pointer sources cannot become a smaller current live counter.
pub(in crate::admission_operation_store::knowledge) fn verify_account(
    tx: &Connection,
    scope: &RecoveryScopeV1,
) -> Result<(), AdmissionOperationStoreError> {
    let (capacity, _) = current_capacity(tx, scope)?;
    let mut live = 0_u64;
    let mut admitted = 0_u64;
    let mut collected = 0_u64;
    super::super::publication_catalog::visit_publication_sources(tx, scope, |record, _| {
        let (lease, _) = current_lease(tx, record)?;
        let actual = collection::collected_source(tx, record)?;
        if actual != lease.collection {
            return Err(refused(
                "publication lease omits its actual terminal collection",
            ));
        }
        if lease.collection.is_none() {
            live = live
                .checked_add(1)
                .ok_or_else(|| refused("publication live inverse exhausted"))?;
        }
        admitted = admitted
            .checked_add(1)
            .ok_or_else(|| refused("publication admission inverse exhausted"))?;
        if lease.collection.is_some() {
            collected = collected
                .checked_add(1)
                .ok_or_else(|| refused("publication collection inverse exhausted"))?;
        }
        verify_object_pointer(tx, record, &lease)?;
        Ok(())
    })?;
    if live != capacity.live()? || admitted != capacity.admitted || collected != capacity.collected
    {
        return Err(refused(
            "publication live counter disagrees with original source custody",
        ));
    }
    let identity = account(scope);
    for prefix in [
        "knowledge-publication-lease",
        "knowledge-publication-object",
    ] {
        let pattern = format!("{prefix}:{}:*", identity.scope_key()?);
        let mut statement = tx.prepare(
            "SELECT record_key FROM admission_operation_recovery_records WHERE record_key GLOB ?1
             UNION SELECT record_key FROM admission_operation_recovery_events WHERE record_key GLOB ?1
             UNION SELECT projection_key FROM authority_global_commits WHERE projection_kind='recovery' AND projection_key GLOB ?1 ORDER BY 1",
        ).map_err(sqlite_error)?;
        let mut rows = statement.query([pattern]).map_err(sqlite_error)?;
        while let Some(row) = rows.next().map_err(sqlite_error)? {
            let key: String = row.get(0).map_err(sqlite_error)?;
            if prefix == "knowledge-publication-lease" {
                let (lease, _) =
                    checked_row::<LeaseRecord>(tx, &key, &identity.scope_key()?, LEASE_BYTES)?;
                let publication = lease.original.record_key();
                let record: NativeArtifactRecordV1 = load(tx, publication)?.ok_or_else(|| {
                    refused("publication lease retained an absent original owner")
                })?;
                if lease.account != identity
                    || key != lease_key(&identity, publication)?
                    || account(&record.metadata.scope) != identity
                {
                    return Err(refused(
                        "publication inverse lease changed its tenant owner",
                    ));
                }
                current_lease(tx, &record)?;
            } else {
                let (pointer, _) =
                    checked_row::<ObjectRecord>(tx, &key, &identity.scope_key()?, LEASE_BYTES)?;
                let record: NativeArtifactRecordV1 =
                    load(tx, &pointer.publication)?.ok_or_else(|| {
                        refused("publication pointer retained an absent original owner")
                    })?;
                if key != object_key(&record.metadata.scope, &record.object)?
                    || account(&record.metadata.scope) != identity
                {
                    return Err(refused(
                        "publication inverse object changed its tenant owner",
                    ));
                }
                let (lease, _) = current_lease(tx, &record)?;
                verify_object_pointer(tx, &record, &lease)?;
            }
        }
    }
    Ok(())
}

fn verify_object_pointer(
    tx: &Connection,
    record: &NativeArtifactRecordV1,
    lease: &LeaseRecord,
) -> Result<(), AdmissionOperationStoreError> {
    let identity = account(&record.metadata.scope);
    let key = object_key(&record.metadata.scope, &record.object)?;
    let (pointer, source) =
        checked_row::<ObjectRecord>(tx, &key, &identity.scope_key()?, LEASE_BYTES)?;
    if source.version() != 1
        || pointer.identity != lease.identity
        || pointer.original != lease.original
        || pointer.publication != record_publication_key(record)?
        || !protected::matches_historical_command_payload(
            tx,
            &key,
            source.scope_key(),
            1,
            &protected::encode(&pointer)?,
        )?
    {
        return Err(refused(
            "publication object pointer changed its original native owner",
        ));
    }
    pointer.original.verify_historical_identity(tx)
}

/// Read-only native source catalog validation. This creates no account,
/// baseline, allowance, retirement authority, or writer proof.
pub(in crate::admission_operation_store) fn verify_catalog(
    tx: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let mut statement = tx.prepare(
        "SELECT record_key FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-publication-capacity:*' OR record_key GLOB 'knowledge-publication-ready:*' OR record_key GLOB 'knowledge-publication-lease:*' OR record_key GLOB 'knowledge-publication-object:*'
         UNION SELECT record_key FROM admission_operation_recovery_events WHERE record_key GLOB 'knowledge-publication-capacity:*' OR record_key GLOB 'knowledge-publication-ready:*' OR record_key GLOB 'knowledge-publication-lease:*' OR record_key GLOB 'knowledge-publication-object:*'
         UNION SELECT projection_key FROM authority_global_commits WHERE projection_kind='recovery' AND (projection_key GLOB 'knowledge-publication-capacity:*' OR projection_key GLOB 'knowledge-publication-ready:*' OR projection_key GLOB 'knowledge-publication-lease:*' OR projection_key GLOB 'knowledge-publication-object:*') ORDER BY 1",
    ).map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    let mut verified = std::collections::BTreeSet::new();
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let key: String = row.get(0).map_err(sqlite_error)?;
        let raw = protected::raw_checked(tx, &key)?
            .ok_or_else(|| refused("publication catalog lost a retained projection"))?;
        let source = protected::source_reference(tx, &key)?;
        let identity = if key.starts_with("knowledge-publication-capacity:") {
            let record: CapacityRecord = protected::decode(&raw.payload)?;
            if key != capacity_key(&record.account)? {
                return Err(refused("publication catalog counter changed its exact key"));
            }
            record.account
        } else if key.starts_with("knowledge-publication-ready:") {
            let record: ReadyRecord = protected::decode(&raw.payload)?;
            if key != ready_key(&record.account)? {
                return Err(refused(
                    "publication catalog readiness changed its exact key",
                ));
            }
            record.account
        } else if key.starts_with("knowledge-publication-lease:") {
            let record: LeaseRecord = protected::decode(&raw.payload)?;
            if key != lease_key(&record.account, record.original.record_key())? {
                return Err(refused("publication catalog lease changed its exact key"));
            }
            record.account
        } else {
            let record: ObjectRecord = protected::decode(&raw.payload)?;
            if key != object_key(&record.identity.reference.scope, &record.identity.object)? {
                return Err(refused("publication catalog object changed its exact key"));
            }
            account(&record.identity.reference.scope)
        };
        let _: (serde_json::Value, _) = checked_row(tx, &key, &identity.scope_key()?, LEASE_BYTES)?;
        if source.scope_key() != identity.scope_key()? || source.kind() != "command" {
            return Err(refused("publication catalog source changed its tenant"));
        }
        if verified.insert(identity.scope_key()?) {
            let scope = installed_account_scope(tx, &identity)?;
            verify_account(tx, &scope)?;
        }
    }
    Ok(())
}

fn installed_account_scope(
    tx: &Connection,
    identity: &ReferenceAccount,
) -> Result<RecoveryScopeV1, AdmissionOperationStoreError> {
    let mut statement = tx.prepare("SELECT record_key FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-profile:*' ORDER BY record_key").map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let key: String = row.get(0).map_err(sqlite_error)?;
        let profile: NativeKnowledgeInstallationV1 = load(tx, &key)?
            .ok_or_else(|| refused("publication catalog installation disappeared"))?;
        let source = protected::source_reference(tx, &key)?;
        if key != profile_key(&profile.scope)?
            || source.kind() != "command"
            || source.scope_key() != scope_key(&profile.scope)?
        {
            return Err(refused(
                "publication catalog installation changed its exact scope",
            ));
        }
        if account(&profile.scope) == *identity {
            return Ok(profile.scope);
        }
    }
    Err(refused(
        "publication catalog account lost its real installation",
    ))
}
