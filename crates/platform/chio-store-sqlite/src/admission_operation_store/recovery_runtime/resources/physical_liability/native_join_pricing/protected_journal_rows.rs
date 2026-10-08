//! Only the genuine staged native journal supplies these protected row shapes.
//! No generic partial-index exemption or writer credit is created here.
use super::*;

pub(super) struct NativeJournalTreeShapesData {
    pub(super) trees: Vec<SqliteTreeWriteShapeData>,
    pub(super) facts: Vec<(String, String, u64, bool)>,
    pub(super) appends: u64,
}

pub(super) fn describe_source_journal_trees(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    source: &VerifiedNativeKnowledgeJoinLiability<'_>,
) -> Result<NativeJournalTreeShapesData, AdmissionOperationStoreError> {
    source.verify_before(tx, owner)?;
    // This exact trusted current catalog includes every applicable expression
    // index and its literal predicate. Unknown source/index SQL is refused.
    physical_command_write_profile(tx)?;
    let chunk_index: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE name='idx_recovery_knowledge_journal_chunk_authority')",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if !chunk_index || source.protected_journal_rows().is_empty() {
        return Err(invariant(
            "native journal lacks its exact current priced catalog",
        ));
    }
    let mut trees = Vec::new();
    let mut facts = Vec::new();
    let mut appends = 0_u64;
    for (key, scope, payload) in source.protected_journal_rows() {
        if key.is_empty()
            || key.chars().count() > 512
            || key.len() > 2_048
            || scope.len() != 64
            || !scope.bytes().all(|byte| byte.is_ascii_hexdigit())
            || payload.is_empty()
            || payload.len() > MAX_RECOVERY_RECORD_BYTES
            || raw_checked(tx, key)?.is_some()
        {
            return Err(invariant(
                "native journal lost its exact pristine source row",
            ));
        }
        let key_bytes = u64::try_from(key.len()).map_err(|error| invariant(error.to_string()))?;
        let payload_bytes =
            u64::try_from(payload.len()).map_err(|error| invariant(error.to_string()))?;
        let journal_chunk = key.starts_with("knowledge-encoding-chunk:");
        if journal_chunk {
            let value: serde_json::Value =
                serde_json::from_slice(payload).map_err(|error| invariant(error.to_string()))?;
            if value
                .pointer("/owner/kind")
                .and_then(serde_json::Value::as_str)
                != Some("journal")
                || value
                    .pointer("/owner/authority")
                    .and_then(serde_json::Value::as_str)
                    != Some(source.journal_authority_id())
            {
                return Err(invariant(
                    "native journal chunk changed its source-owned index key",
                ));
            }
        } else if !key.starts_with("knowledge-join:") {
            return Err(invariant(
                "native journal names another protected writer family",
            ));
        }
        // Recovery records are a rowid table with a separate TEXT primary key
        // and scope index. The command's native identity is NULL; its prefix is
        // disjoint from all four original-owner and other priced partial keys.
        fresh(
            &mut trees,
            record_bytes(&[key_bytes, 64, 7, 8, payload_bytes, 0, 0])?,
        )?;
        fresh(&mut trees, record_bytes(&[key_bytes, 8])?)?;
        fresh(&mut trees, record_bytes(&[64, 7, 8])?)?;
        if journal_chunk {
            fresh(
                &mut trees,
                record_bytes(&[
                    u64::try_from(source.journal_authority_id().len())
                        .map_err(|error| invariant(error.to_string()))?,
                    8,
                ])?,
            )?;
        }
        // One immutable event table row and its actual UNIQUE(key,version)
        // index accompany each command. INTEGER PRIMARY KEY is the table tree.
        fresh(&mut trees, record_bytes(&[8, key_bytes, 8, 64, 64, 64, 8])?)?;
        fresh(&mut trees, record_bytes(&[key_bytes, 8, 8])?)?;
        // Exact current40 recovery_transition global framing has twelve cells.
        // This actual write uses the source owner's retained current fence;
        // another producer or future framing cannot reuse this descriptor.
        fresh(
            &mut trees,
            record_bytes(&[
                8,
                u64::try_from("recovery_transition".len())
                    .map_err(|error| invariant(error.to_string()))?,
                u64::try_from("recovery".len()).map_err(|error| invariant(error.to_string()))?,
                key_bytes,
                8,
                64,
                64,
                64,
                64,
                u64::try_from(owner.fence.store_uuid.len())
                    .map_err(|error| invariant(error.to_string()))?,
                u64::try_from(owner.fence.lease_id.len())
                    .map_err(|error| invariant(error.to_string()))?,
                8,
            ])?,
        )?;
        fresh(&mut trees, record_bytes(&[8, key_bytes, 8, 8])?)?;
        appends = appends
            .checked_add(1)
            .ok_or_else(|| invariant("native journal append bound exhausted"))?;
        facts.push((
            key.clone(),
            sha256_hex(payload),
            payload_bytes,
            journal_chunk,
        ));
    }
    // Authenticated global meta is an existing INTEGER PRIMARY KEY singleton,
    // no secondary index, and this complete row fits every supported root.
    trees.push(
        SqliteTreeWriteShapeData::singleton_root(record_bytes(&[8, 8, 64])?, appends)
            .map_err(invariant)?,
    );
    Ok(NativeJournalTreeShapesData {
        trees,
        facts,
        appends,
    })
}

fn fresh(
    trees: &mut Vec<SqliteTreeWriteShapeData>,
    maximum_record_bytes: u64,
) -> Result<(), AdmissionOperationStoreError> {
    trees.push(
        SqliteTreeWriteShapeData::fresh_insertions(maximum_record_bytes, 1).map_err(invariant)?,
    );
    Ok(())
}

fn record_bytes(cells: &[u64]) -> Result<u64, AdmissionOperationStoreError> {
    let header = u64::try_from(cells.len())
        .map_err(|error| invariant(error.to_string()))?
        .checked_mul(9)
        .and_then(|bytes| bytes.checked_add(1))
        .ok_or_else(|| invariant("native journal record header exhausted"))?;
    cells.iter().try_fold(header, |sum, cell| {
        sum.checked_add(*cell)
            .ok_or_else(|| invariant("native journal record body exhausted"))
    })
}
