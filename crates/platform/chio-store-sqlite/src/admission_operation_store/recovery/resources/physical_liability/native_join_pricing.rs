//! Exact native join row and journal prices are DATA, never a funded purpose.
use super::*;
use crate::admission_operation_store::raw_custody_liability::raw_write_profile;
use crate::admission_operation_store::security_participant_state::knowledge::liability::{
    NativeWriteTableData, VerifiedNativeKnowledgeJoinLiability,
};
use chio_sqlite_file_identity::{
    price_transaction_write_shape, write_price_algorithm_descriptor, SqliteFramePriceProfileData,
    SqliteTransactionWriteShapeData, SqliteTreeWriteShapeData,
};

mod protected_journal_rows;
const SERVING_ANCHOR_BYTES: u64 = 2 * 1_024;

pub(in crate::admission_operation_store) struct NativeKnowledgeJoinPriceData {
    physical: PhysicalLiabilityData,
    journal_records: u64,
    journal_bytes: u64,
    profile: String,
}

impl NativeKnowledgeJoinPriceData {
    pub(in crate::admission_operation_store) fn physical(&self) -> &PhysicalLiabilityData {
        &self.physical
    }

    pub(in crate::admission_operation_store) fn journal_records(&self) -> u64 {
        self.journal_records
    }

    pub(in crate::admission_operation_store) fn journal_bytes(&self) -> u64 {
        self.journal_bytes
    }

    pub(in crate::admission_operation_store) fn profile(&self) -> &str {
        &self.profile
    }
}

/// Both real source catalogs and the actual borrowed source cut are required.
/// All root/chunk rows retain their own command history costs even when the
/// writer commits them together. No future-growth or generation-only credit
/// can be supplied by a caller. Future original Output has a separate census.
pub(in crate::admission_operation_store) fn price_native_knowledge_join_liability(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    source: &VerifiedNativeKnowledgeJoinLiability<'_>,
) -> Result<NativeKnowledgeJoinPriceData, AdmissionOperationStoreError> {
    source.verify_before(tx, owner)?;
    let flow_catalog =
        crate::admission_operation_store::security_participant_state::schema::native_flow_write_catalog(tx)?;
    if flow_catalog.fingerprint() != source.native_catalog_fingerprint() {
        return Err(invariant("native join price changed its actual catalog"));
    }
    // This existing real profile authenticates the pinned SQLite source,
    // namespace, UTF-8, FULL WAL, auto-vacuum0, pending reserve0 and Unix VFS.
    // A standalone source without these actual tables cannot borrow the price.
    let geometry = raw_write_profile(tx)?;
    let command_catalog = physical_command_write_profile(tx)?;
    let frame_profile =
        SqliteFramePriceProfileData::checked(geometry.page_size(), 0).map_err(invariant)?;
    let mut trees = Vec::new();
    let mut facts = Vec::new();
    for row in source.native_write_shapes() {
        let before = row.before_record_bytes();
        let after = row.maximum_after_record_bytes();
        let mutations = row.source_mutations();
        if row.existed() != before.is_some()
            || after == 0
            || row.maximum_record_bytes() < before.unwrap_or(0).max(after)
        {
            return Err(invariant("native join price lost its actual row images"));
        }
        trees.push(SqliteTreeWriteShapeData::record(before, after, mutations).map_err(invariant)?);
        // All eight closed flow tables are WITHOUT ROWID. Their primary key
        // already belongs to this table tree. IsolationEpochs alone has a
        // secondary UNIQUE tree. Its key is a subset of the complete row, so
        // retaining the full before/after payload safely overprices that key.
        let secondary_trees = u8::from(row.table() == NativeWriteTableData::IsolationEpochs);
        if secondary_trees == 1 {
            trees.push(
                SqliteTreeWriteShapeData::record(before, after, mutations).map_err(invariant)?,
            );
        }
        facts.push((
            row.table().table_name(),
            row.primary_key(),
            before,
            after,
            mutations,
            secondary_trees,
        ));
    }
    if trees.is_empty() {
        return Err(invariant(
            "native join price lost its producing source rows",
        ));
    }
    let journal = protected_journal_rows::describe_source_journal_trees(tx, owner, source)?;
    trees.extend(journal.trees);
    // These native and journal writes belong to this one actual producer
    // transaction. Every mutation/history tree remains individually charged;
    // transaction framing and FULL WAL padding are charged once for this cut.
    let priced = price_transaction_write_shape(
        &frame_profile,
        &SqliteTransactionWriteShapeData::checked(trees).map_err(invariant)?,
    )
    .map_err(invariant)?;
    let physical = PhysicalLiabilityData {
        wal_bytes: priced.wal_bytes(),
        disk_bytes: priced
            .disk_bytes()
            .checked_add(SERVING_ANCHOR_BYTES)
            .ok_or_else(|| invariant("native join anchor disk bound exhausted"))?,
        recovery_appends: journal.appends,
        global_appends: journal.appends,
    };
    physical.validate()?;
    let profile = sha256_hex(
        &canonical_json_bytes(&(
            "chio.sqlite.native-knowledge-frame-price.v3",
            geometry.fingerprint(),
            flow_catalog.fingerprint(),
            command_catalog.fingerprint(),
            write_price_algorithm_descriptor(),
            facts,
            journal.facts,
            (
                "source-issued pristine journal rows; header9_per_cell; current40 recovery_transition; matching journal_chunk_authority_expression_index",
                owner.fence.store_uuid.len(), owner.fence.lease_id.len(),
                source.journal_authority_id().len(), SERVING_ANCHOR_BYTES,
            ),
            source.journal_records(),
            source.journal_bytes(),
            "each root and chunk retains all event/global/index costs; repeated spilling charged; no before-image reuse credit",
        ))
        .map_err(|error| invariant(error.to_string()))?,
    );
    Ok(NativeKnowledgeJoinPriceData {
        physical,
        journal_records: source.journal_records(),
        journal_bytes: source.journal_bytes(),
        profile,
    })
}
