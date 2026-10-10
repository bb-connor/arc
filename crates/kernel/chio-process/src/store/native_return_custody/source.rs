//! Actual original call checks precede the deliberately closed registration.
use super::*;

pub(super) fn verify_prepared_pricing_cut(
    tx: &Transaction<'_>,
    source: &PreparedProcessReturnSource,
) -> Result<(), ProcessError> {
    let connection: &Connection = tx;
    let address = std::ptr::from_ref(connection) as usize;
    let profile = catalog::prepare_profile(
        tx,
        &source.path,
        &source.data.journal_namespace,
        &source.data.journal_authority,
        &source.kernel_key,
    )?;
    if tx.is_autocommit()
        || address != source.prepared_connection
        || tx.total_changes() != source.prepared_total_changes
        || profile.recipe_digest() != source.profile.recipe_digest()
        || profile.file_device() != source.data.file_device
        || profile.file_inode() != source.data.file_inode
        || profile.catalog_digest() != source.data.catalog_digest
        || digest(&source.kernel_key)? != source.data.kernel_key_digest
        || source_row_digest(tx, &source.data)? != source.rows_digest
    {
        return Err(ProcessError::Conflict);
    }
    Ok(())
}

fn source_row_digest(
    tx: &Connection,
    source: &ProcessReturnSourceDataV1,
) -> Result<String, ProcessError> {
    let (binding, attempt): (String,u32) = tx.query_row(
        "SELECT request_hash,attempts FROM main.process_calls WHERE process_id=?1 AND operation_key=?2",
        params![source.process_id,source.operation_key], |row| Ok((row.get(0)?,row.get(1)?)),
    )?;
    if binding != source.call_binding_digest || attempt != source.attempt {
        return Err(ProcessError::Conflict);
    }
    let mut statement = tx.prepare(
        "SELECT id,parent_id,root_id,depth,CASE WHEN typeof(capability)='text' AND length(CAST(capability AS BLOB)) BETWEEN 1 AND 262144 THEN capability END,CASE WHEN typeof(limits)='text' AND length(CAST(limits AS BLOB)) BETWEEN 1 AND 4096 THEN limits END,state,revision,CASE WHEN typeof(checkpoint)='text' AND length(CAST(checkpoint AS BLOB)) BETWEEN 1 AND 1048576 THEN checkpoint END,tree_calls FROM main.processes WHERE id=?1 OR id=?2 ORDER BY id",
    )?;
    let mut query = statement.query(params![source.process_id, source.root_process_id])?;
    let mut records = Vec::new();
    while let Some(row) = query.next()? {
        let record = (
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, u32>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            u64::try_from(row.get::<_, i64>(7)?).map_err(|_| ProcessError::Conflict)?,
            row.get::<_, String>(8)?,
            u64::try_from(row.get::<_, i64>(9)?).map_err(|_| ProcessError::Conflict)?,
        );
        records.push(record);
    }
    let expected_records = if source.process_id == source.root_process_id {
        1
    } else {
        2
    };
    if records.len() != expected_records {
        return Err(ProcessError::Conflict);
    }
    let nonce: Option<Vec<u8>> = tx.query_row(
        "SELECT CASE WHEN typeof(nonce_json)='blob' AND length(nonce_json) BETWEEN 1 AND 16384 THEN nonce_json END FROM main.process_call_nonces WHERE process_id=?1 AND operation_key=?2 AND attempt=?3",
        params![source.process_id,source.operation_key,source.attempt], |row| row.get(0),
    ).optional()?;
    let nonce_digest = nonce
        .as_ref()
        .map(|bytes| chio_core_types::crypto::sha256_hex(bytes));
    if nonce_digest != source.original_nonce_digest {
        return Err(ProcessError::Conflict);
    }
    digest(&(
        "chio.process-native-return-row-cut.v1",
        records,
        binding,
        attempt,
        nonce_digest,
    ))
}

pub(super) fn verify_source_request(
    store: &Store,
    runtime: &ProcessRuntime,
    process_id: &str,
    operation_key: &str,
    request: &ToolCallRequest,
    binding: &ProcessCallBinding,
    known_outcome_only: bool,
    security_context: Option<&chio_kernel::SecurityInvocationContext>,
) -> Result<(), ProcessError> {
    crate::validate_id(process_id)?;
    crate::validate_id(operation_key)?;
    if runtime.namespace != store.namespace {
        return Err(ProcessError::Conflict);
    }
    let actual_binding =
        runtime.derive_call_binding(process_id, operation_key, request, known_outcome_only)?;
    if actual_binding.request_hash != binding.request_hash
        || actual_binding.binding_hash != binding.binding_hash
    {
        return Err(ProcessError::Conflict);
    }
    let process = store.process(process_id)?;
    require_running(&process)?;
    crate::verify_capability(&process.capability)?;
    if digest(&process.capability)? != digest(&request.capability)?
        || request.agent_id != process.capability.subject.to_hex()
    {
        return Err(ProcessError::Conflict);
    }
    let (stored_binding, attempt): (String, u32) = store.connection.query_row(
        "SELECT request_hash,attempts FROM main.process_calls WHERE process_id=?1 AND operation_key=?2",
        params![process_id, operation_key], |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if stored_binding != binding.binding_hash
        || !(1..=crate::MAX_DISPATCH_ATTEMPTS).contains(&attempt)
        || request.request_id
            != runtime.request_id_for_attempt(process_id, operation_key, attempt)?
    {
        return Err(ProcessError::Conflict);
    }
    // Exact ancestry is read from the owning journal. The source factory must
    // also use this lineage for the host-selected confined context, not accept
    // a caller-selected principal, root or role-map descriptor.
    let (original, lineage) = store.retained_lineage(process_id)?;
    if original.root_id != process.root_id || lineage.is_empty() {
        return Err(ProcessError::Conflict);
    }
    for capability in &lineage {
        crate::verify_capability(capability)?;
    }
    // Native context selection occurs outside the Process mutex. The owning
    // native source plan independently checks the supplied context against its
    // actual original. This local DATA check performs no native callback or
    // current-actor authentication while holding the Process writer.
    if let Some(context) = security_context {
        let bytes = chio_core_types::canonical_json_bytes(context)?;
        if bytes.is_empty() || bytes.len() > MAX_SOURCE_BYTES {
            return Err(ProcessError::Conflict);
        }
    }
    let actual_authority = runtime
        .kernel
        .durable_admission_store_uuid()
        .ok_or(ProcessError::Conflict)?;
    let (namespace, authority, key): (String, String, String) = store.connection.query_row(
        "SELECT namespace,authority,kernel_key FROM main.process_runtime WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if namespace != store.namespace
        || authority != actual_authority
        || key != runtime.kernel.public_key().to_hex()
    {
        return Err(ProcessError::Conflict);
    }
    store.original_snapshot(&authority, &key).verify_path()?;
    super::super::unused_recovery_reservation::verify_before_open(&store.connection)?;
    super::super::confined_delivery::verify_before_open(&store.connection)?;
    Ok(())
}
