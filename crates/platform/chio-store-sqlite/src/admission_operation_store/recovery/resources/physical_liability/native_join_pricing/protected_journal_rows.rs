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
    let release_index: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE name='idx_recovery_knowledge_join_release')",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if !chunk_index || !release_index || source.protected_journal_rows().is_empty() {
        return Err(invariant(
            "native journal lacks its exact current priced catalog",
        ));
    }
    let journal_authority = source.journal_authority_id();
    let journal_release = source.journal_release_id();
    let mut trees = Vec::new();
    let mut facts = Vec::new();
    let mut appends = 0_u64;
    for (key, scope, payload) in source.protected_journal_rows() {
        if raw_checked(tx, key)?.is_some() {
            return Err(invariant(
                "native journal lost its exact pristine source row",
            ));
        }
        let (row_trees, journal_chunk, key_bytes, payload_bytes) =
            priced_row_trees(key, scope, payload, journal_authority, journal_release)?;
        trees.extend(row_trees);
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

/// Projection rows share the journal's recovery record, event and index
/// trees, but a repeated join updates an existing slot instead of inserting
/// a pristine row: the before image is priced alongside the successor. Every
/// tree is charged per mutation; no before-image reuse credit exists.
pub(super) fn describe_scope_projection_trees(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    source: &VerifiedNativeKnowledgeJoinLiability<'_>,
) -> Result<NativeJournalTreeShapesData, AdmissionOperationStoreError> {
    source.verify_before(tx, owner)?;
    physical_command_write_profile(tx)?;
    if source.projection_writes().is_empty() {
        return Err(invariant(
            "native join lost its inherited-scope projection mutations",
        ));
    }
    let mut trees = Vec::new();
    let mut facts = Vec::new();
    let mut appends = 0_u64;
    // The projection record key is authority prefixed: an update keeps the
    // slot's exact identity, and this prefix is the priced key layout.
    let prefix = crate::admission_operation_store::security_participant_state::knowledge::influence_slots::authority_slot_prefix(
        source.journal_authority_id(),
    );
    for write in source.projection_writes() {
        let key = write.record_key();
        let scope = write.scope_key();
        let before = write
            .before_payload()
            .map(|before| u64::try_from(before.len()).map_err(|error| invariant(error.to_string())))
            .transpose()?;
        let after = u64::try_from(write.after_payload().len())
            .map_err(|error| invariant(error.to_string()))?;
        let slot_digest = key.strip_prefix(prefix.as_str()).unwrap_or("");
        if key.is_empty()
            || slot_digest.len() != 64
            || !slot_digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            || scope.len() != 64
            || !scope.bytes().all(|byte| byte.is_ascii_hexdigit())
            || write.after_payload().is_empty()
            || write.after_payload().len() > MAX_RECOVERY_RECORD_BYTES
            || write.after_payload().len()
                > crate::admission_operation_store::security_participant_state::knowledge::influence_slots::MAX_NATIVE_INFLUENCE_PAYLOAD_BYTES
        {
            return Err(invariant(
                "native projection lost its exact priced source row",
            ));
        }
        let key_bytes = u64::try_from(key.len()).map_err(|error| invariant(error.to_string()))?;
        // The current recovery row: an update retains its before image, a new
        // slot inserts fresh. The unique key tree and the scope index tree
        // both move for either shape.
        let before_record = before
            .map(|bytes| record_bytes(&[key_bytes, 64, 7, 8, bytes, 0, 0]))
            .transpose()?;
        let after_record = record_bytes(&[key_bytes, 64, 7, 8, after, 0, 0])?;
        trees.push(
            SqliteTreeWriteShapeData::record(before_record, after_record, 1).map_err(invariant)?,
        );
        fresh(&mut trees, record_bytes(&[key_bytes, 8])?)?;
        fresh(&mut trees, record_bytes(&[64, 7, 8])?)?;
        // One immutable event row and its actual UNIQUE(key,version) index
        // accompany each command. INTEGER PRIMARY KEY is the table tree.
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
            .ok_or_else(|| invariant("native projection append bound exhausted"))?;
        facts.push((
            key.to_owned(),
            sha256_hex(write.after_payload()),
            after,
            false,
        ));
    }
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

/// One pristine journal row's priced B-trees and its exact source identity:
/// the shared record, unique-key and scope trees, plus its family's real
/// expression index tree. A chunk moves the journal_chunk_authority index; a
/// join root moves the release lookup index and must carry its source-owned
/// release identity at $.release.release. No guessed identifier or writer
/// credit exists here; the caller owns the actual staged source cut.
fn priced_row_trees(
    key: &str,
    scope: &str,
    payload: &[u8],
    journal_authority: &str,
    journal_release: &str,
) -> Result<(Vec<SqliteTreeWriteShapeData>, bool, u64, u64), AdmissionOperationStoreError> {
    if key.is_empty()
        || key.chars().count() > 512
        || key.len() > 2_048
        || scope.len() != 64
        || !scope.bytes().all(|byte| byte.is_ascii_hexdigit())
        || payload.is_empty()
        || payload.len() > MAX_RECOVERY_RECORD_BYTES
    {
        return Err(invariant(
            "native journal lost its exact pristine source row",
        ));
    }
    let key_bytes = u64::try_from(key.len()).map_err(|error| invariant(error.to_string()))?;
    let payload_bytes =
        u64::try_from(payload.len()).map_err(|error| invariant(error.to_string()))?;
    let journal_chunk = key.starts_with("knowledge-encoding-chunk:");
    let journal_join = key.starts_with("knowledge-join:");
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
                != Some(journal_authority)
        {
            return Err(invariant(
                "native journal chunk changed its source-owned index key",
            ));
        }
    } else if journal_join {
        let value: serde_json::Value =
            serde_json::from_slice(payload).map_err(|error| invariant(error.to_string()))?;
        if value
            .pointer("/release/release")
            .and_then(serde_json::Value::as_str)
            != Some(journal_release)
        {
            return Err(invariant(
                "native journal root changed its source-owned release identity",
            ));
        }
    } else {
        return Err(invariant(
            "native journal names another protected writer family",
        ));
    }
    let mut trees = Vec::new();
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
                u64::try_from(journal_authority.len())
                    .map_err(|error| invariant(error.to_string()))?,
                8,
            ])?,
        )?;
    }
    if journal_join {
        // The release lookup index moves once for this root row: the encoded
        // release string plus the rowid. Chunks are outside this partial
        // index and keep their own chunk-authority cost above.
        fresh(
            &mut trees,
            record_bytes(&[
                u64::try_from(journal_release.len())
                    .map_err(|error| invariant(error.to_string()))?,
                8,
            ])?,
        )?;
    }
    Ok((trees, journal_chunk, key_bytes, payload_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    const SCOPE: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn root_payload(release: &str) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(&serde_json::json!({ "release": { "release": release } }))
    }

    fn chunk_payload(authority: &str) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(&serde_json::json!({
            "knowledge_chunk_encoding": "label_atoms_v1",
            "owner": { "kind": "journal", "authority": authority }
        }))
    }

    #[test]
    fn journal_root_charges_its_real_release_expression_index_tree() -> TestResult {
        let (trees, chunk, _, _) = priced_row_trees(
            "knowledge-join:aaa:0000000000000001",
            SCOPE,
            &root_payload("release-identity")?,
            "journal-authority",
            "release-identity",
        )?;
        assert!(!chunk);
        // Shared record, unique-key and scope trees, plus the release index.
        assert_eq!(trees.len(), 4);
        let release_tree = SqliteTreeWriteShapeData::fresh_insertions(
            record_bytes(&[u64::try_from("release-identity".len())?, 8])?,
            1,
        )?;
        assert!(
            trees.contains(&release_tree),
            "the join root must charge its real release expression index B-tree"
        );
        Ok(())
    }

    #[test]
    fn journal_chunk_keeps_its_chunk_authority_cost_without_a_release_tree() -> TestResult {
        let (trees, chunk, _, _) = priced_row_trees(
            "knowledge-encoding-chunk:aaa:0000000000000000000000000000000000000000000000000000000000000000:0000",
            SCOPE,
            &chunk_payload("journal-authority")?,
            "journal-authority",
            "release-identity",
        )?;
        assert!(chunk);
        // Shared record, unique-key and scope trees, plus the chunk index.
        assert_eq!(trees.len(), 4);
        let release_tree = SqliteTreeWriteShapeData::fresh_insertions(
            record_bytes(&[u64::try_from("release-identity".len())?, 8])?,
            1,
        )?;
        assert!(
            !trees.contains(&release_tree),
            "a chunk is outside the release partial index and keeps only its own cost"
        );
        let chunk_tree = SqliteTreeWriteShapeData::fresh_insertions(
            record_bytes(&[u64::try_from("journal-authority".len())?, 8])?,
            1,
        )?;
        assert!(trees.contains(&chunk_tree));
        Ok(())
    }

    #[test]
    fn journal_root_refuses_a_mismatched_or_absent_source_release_identity() -> TestResult {
        assert!(priced_row_trees(
            "knowledge-join:aaa:0000000000000001",
            SCOPE,
            &root_payload("other-release")?,
            "journal-authority",
            "release-identity",
        )
        .is_err());
        assert!(priced_row_trees(
            "knowledge-join:aaa:0000000000000001",
            SCOPE,
            &root_payload("release-identity")?,
            "journal-authority",
            "other-release",
        )
        .is_err());
        assert!(priced_row_trees(
            "knowledge-join:aaa:0000000000000001",
            SCOPE,
            serde_json::to_vec(&serde_json::json!({ "labels": {} }))?.as_slice(),
            "journal-authority",
            "release-identity",
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn journal_row_refuses_other_families_and_lost_row_bounds() -> TestResult {
        assert!(priced_row_trees(
            "knowledge-restore:aaa:0000000000000001",
            SCOPE,
            &root_payload("release-identity")?,
            "journal-authority",
            "release-identity",
        )
        .is_err());
        assert!(priced_row_trees(
            "knowledge-encoding-chunk:aaa:0000000000000000000000000000000000000000000000000000000000000000:0000",
            SCOPE,
            &chunk_payload("other-authority")?,
            "journal-authority",
            "release-identity",
        )
        .is_err());
        for (key, scope, payload) in [
            ("", SCOPE, root_payload("release-identity")?.as_slice()),
            (
                "knowledge-join:aaa:0000000000000001",
                "0",
                root_payload("release-identity")?.as_slice(),
            ),
            ("knowledge-join:aaa:1", SCOPE, [].as_slice()),
        ] {
            assert!(
                priced_row_trees(key, scope, payload, "journal-authority", "release-identity")
                    .is_err()
            );
        }
        Ok(())
    }
}
