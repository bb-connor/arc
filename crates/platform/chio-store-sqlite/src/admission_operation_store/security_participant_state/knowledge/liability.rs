//! Actual native join shapes borrow their authenticated physical source cut.
use super::*;
use crate::admission_operation_store::recovery::resources::ProtectedCommandLiabilityPlan;
use crate::security_state::{
    decode_retained_security_row, retained_security_columns, NativeFlowJoinPreview,
};
use crate::serving_owner::NativeSourceTransactionOrigin;
use rusqlite::types::Value;
use std::collections::BTreeMap;
mod row_footprint;

/// The source fixes the table vocabulary. A caller cannot supply SQL tables,
/// indexes, page prices or a byte allowance to a native write descriptor.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::admission_operation_store) enum NativeWriteTableData {
    FlowContexts,
    FlowSequences,
    IsolationEpochs,
    PrincipalLabels,
    LineageLabels,
    SessionLabels,
    SessionMemberships,
    FlowTransitions,
}

impl NativeWriteTableData {
    pub(in crate::admission_operation_store) fn table_name(self) -> &'static str {
        match self {
            Self::FlowContexts => "security_participant_state_flow_contexts",
            Self::FlowSequences => "security_participant_state_flow_sequences",
            Self::IsolationEpochs => "security_participant_state_isolation_epochs",
            Self::PrincipalLabels => "security_participant_state_principal_flow_state",
            Self::LineageLabels => "security_participant_state_lineage_flow_state",
            Self::SessionLabels => "security_participant_state_session_flow_state",
            Self::SessionMemberships => "security_participant_state_session_memberships",
            Self::FlowTransitions => "security_participant_state_transitions",
        }
    }

    fn from_source(table: &str) -> Result<Self, AdmissionOperationStoreError> {
        match table {
            "security_flow_contexts" => Ok(Self::FlowContexts),
            "security_flow_sequences" => Ok(Self::FlowSequences),
            "security_isolation_epochs" => Ok(Self::IsolationEpochs),
            "security_principal_flow_state" => Ok(Self::PrincipalLabels),
            "security_lineage_flow_state" => Ok(Self::LineageLabels),
            "security_session_flow_state" => Ok(Self::SessionLabels),
            "security_session_memberships" => Ok(Self::SessionMemberships),
            "security_transitions" => Ok(Self::FlowTransitions),
            _ => Err(invalid(
                "native liability names an unsupported source table",
            )),
        }
    }

    fn source_keys(self) -> &'static [&'static str] {
        match self {
            Self::FlowContexts => &[
                "tenant_id",
                "principal_id",
                "lineage_id",
                "session_id",
                "isolation_epoch_id",
            ],
            Self::FlowSequences => &["tenant_id"],
            Self::IsolationEpochs => &[
                "tenant_id",
                "principal_id",
                "lineage_id",
                "isolation_epoch_id",
            ],
            Self::PrincipalLabels => &["tenant_id", "principal_id", "isolation_epoch_id"],
            Self::LineageLabels => &["tenant_id", "lineage_id"],
            Self::SessionLabels | Self::SessionMemberships => &[
                "tenant_id",
                "principal_id",
                "session_id",
                "isolation_epoch_id",
            ],
            Self::FlowTransitions => &["tenant_id", "transition_id"],
        }
    }
}

/// One actual changed primary key. Overlapping invalidations retain their
/// journal multiplicity but share this physical row and its B-tree ancestors.
pub(in crate::admission_operation_store) struct NativeWriteShapeData {
    table: NativeWriteTableData,
    primary_key: Vec<(&'static str, String)>,
    existed: bool,
    generation_only: bool,
    before_record_bytes: Option<u64>,
    maximum_after_record_bytes: u64,
    maximum_record_bytes: u64,
    source_mutations: u64,
}

impl NativeWriteShapeData {
    pub(in crate::admission_operation_store) fn table(&self) -> NativeWriteTableData {
        self.table
    }
    pub(in crate::admission_operation_store) fn primary_key(&self) -> &[(&'static str, String)] {
        &self.primary_key
    }
    pub(in crate::admission_operation_store) fn existed(&self) -> bool {
        self.existed
    }
    pub(in crate::admission_operation_store) fn generation_only(&self) -> bool {
        self.generation_only
    }
    pub(in crate::admission_operation_store) fn before_record_bytes(&self) -> Option<u64> {
        self.before_record_bytes
    }
    pub(in crate::admission_operation_store) fn maximum_after_record_bytes(&self) -> u64 {
        self.maximum_after_record_bytes
    }
    pub(in crate::admission_operation_store) fn maximum_record_bytes(&self) -> u64 {
        self.maximum_record_bytes
    }
    pub(in crate::admission_operation_store) fn source_mutations(&self) -> u64 {
        self.source_mutations
    }
}

/// This role is neither a phase reservation nor credit. It survives the move
/// of the actual Transaction wrapper while retaining its connection and cut.
/// Construction is private to this real native source, with no serde or Clone.
pub(in crate::admission_operation_store) struct VerifiedNativeKnowledgeJoinLiability<'owner> {
    owner: &'owner SqliteServingOwner,
    origin: NativeSourceTransactionOrigin<'owner>,
    initialized: SecurityParticipantStateInitialization,
    preview: NativeFlowJoinPreview,
    record: Record,
    initial_global_head: (i64, String),
    native_catalog_fingerprint: String,
    native_shapes: Vec<NativeWriteShapeData>,
    protected_rows: Vec<(String, String, Vec<u8>)>,
    protected_commands: Vec<ProtectedCommandLiabilityPlan>,
    retained_journal: (u64, u64),
    journal_bytes: u64,
}

pub(in crate::admission_operation_store) fn prepare_native_knowledge_join_liability<'owner>(
    tx: &Transaction<'_>,
    owner: &'owner SqliteServingOwner,
    origin: &NativeSourceTransactionOrigin<'owner>,
    input: &KnowledgeJoin<'_>,
) -> Result<VerifiedNativeKnowledgeJoinLiability<'owner>, AdmissionOperationStoreError> {
    origin.verify(tx).map_err(map_owner_error)?;
    if !origin.matches_owner(owner) || input.binding.store_uuid().as_str() != owner.fence.store_uuid
    {
        return Err(invalid("native knowledge liability changed its real owner"));
    }
    let native_catalog_fingerprint = super::super::schema::native_flow_write_catalog(tx)?
        .fingerprint()
        .to_owned();
    super::super::super::schema::verify_active_owner(tx, owner, Some(&owner.fence))?;
    let initialized = records::load_current_metadata(tx, input.binding)?;
    let authority = initialized.authority.as_str();
    let transition =
        RecordId::new(input.release.observation_transition.as_str()).map_err(invalid)?;
    let request = crate::security_state::resolve_native_label_join(
        tx,
        authority,
        input.key,
        input.source,
        &transition,
    )
    .map_err(invalid)?;
    let preview = crate::security_state::preview_native_flow_join(tx, authority, &request)
        .map_err(invalid)?;
    let sequence = head(tx, authority)?
        .checked_add(1)
        .ok_or_else(|| invalid("native knowledge liability sequence overflow"))?;
    let previous = if sequence == 1 {
        initialized.digest.clone()
    } else {
        load_with_digest(tx, authority, sequence - 1)?.1
    };
    let (current_rows, current_bytes) = apply_totals(
        history::ordered::latest_totals(tx, &initialized)?,
        preview.changes(),
    )?;
    let mut release = input.release.clone();
    release.source_label = request.principal_join.clone();
    release.observation_generation =
        chio_security_types::recovery::SafeInteger::new(preview.result().context_generation)
            .map_err(invalid)?;
    let record = Record {
        authority: authority.into(),
        initialization: initialized.digest.clone(),
        sequence,
        previous,
        observed_at: input.now,
        scope: input.scope.clone(),
        release,
        request,
        result: preview.result().clone(),
        changes: BoundedVec::new(preview.changes().to_vec()).map_err(invalid)?,
        current_rows,
        current_bytes,
    };
    record.validate()?;
    let protected_rows = encoding::preview_rows(&record)?;
    let mut protected_commands = Vec::with_capacity(protected_rows.len());
    let mut journal_bytes = 0_u64;
    for (key, scope, payload) in &protected_rows {
        let bytes = u64::try_from(payload.len()).map_err(invalid)?;
        // The journal's existing chunk inventory has its own bound. A command
        // batch ceiling must not become a new native journal cardinality cap.
        let mut command = ProtectedCommandLiabilityPlan::new();
        command.add_new_command(tx, key, scope, bytes)?;
        protected_commands.push(command);
        journal_bytes = journal_bytes
            .checked_add(bytes)
            .ok_or_else(|| invalid("native knowledge liability bytes overflow"))?;
    }
    let retained_journal = history::ordered::journal_totals(tx, authority)?;
    if retained_journal
        .0
        .checked_add(1)
        .is_none_or(|count| count > 65_536)
        || retained_journal
            .1
            .checked_add(journal_bytes)
            .is_none_or(|bytes| bytes > 67_108_864)
    {
        return Err(invalid(
            "proposed native knowledge journal exceeds retained source bounds",
        ));
    }
    let native_shapes = write_shapes(authority, preview.changes())?;
    let initial_global_head = global_head(tx)?;
    #[cfg(feature = "admission-test-support")]
    read_work_test_support::knowledge_join_preview();
    Ok(VerifiedNativeKnowledgeJoinLiability {
        owner,
        origin: origin.fork_for_source(),
        initialized,
        preview,
        record,
        initial_global_head,
        native_catalog_fingerprint,
        native_shapes,
        protected_rows,
        protected_commands,
        retained_journal,
        journal_bytes,
    })
}

impl VerifiedNativeKnowledgeJoinLiability<'_> {
    pub(in crate::admission_operation_store) fn verify_before(
        &self,
        tx: &Transaction<'_>,
        owner: &SqliteServingOwner,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.verify_owner(tx, owner)?;
        if super::super::schema::native_flow_write_catalog(tx)?.fingerprint()
            != self.native_catalog_fingerprint
            || global_head(tx)? != self.initial_global_head
            || records::load_current_metadata(tx, &self.initialized.admission_binding()?)?
                != self.initialized
            || history::ordered::journal_totals(tx, self.initialized.authority.as_str())?
                != self.retained_journal
        {
            return Err(invalid(
                "native knowledge liability changed its initial source cut",
            ));
        }
        let actual = crate::security_state::preview_native_flow_join(
            tx,
            self.initialized.authority.as_str(),
            &self.record.request,
        )
        .map_err(invalid)?;
        self.preview
            .verify_actual(actual.result(), actual.changes())
            .map_err(invalid)?;
        for (key, _, _) in &self.protected_rows {
            if protected::raw_checked(tx, key)?.is_some() {
                return Err(invalid(
                    "native knowledge liability lost a pristine journal member",
                ));
            }
        }
        Ok(())
    }

    fn verify_owner(
        &self,
        tx: &Transaction<'_>,
        owner: &SqliteServingOwner,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.origin.verify(tx).map_err(map_owner_error)?;
        if !std::ptr::eq(self.owner, owner) || !self.origin.matches_owner(owner) {
            return Err(invalid(
                "native knowledge liability changed its actual writer",
            ));
        }
        super::super::super::schema::verify_active_owner(tx, owner, Some(&owner.fence))
    }

    pub(super) fn verify_native_result(
        &self,
        tx: &Transaction<'_>,
        owner: &SqliteServingOwner,
        record: &Record,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.verify_owner(tx, owner)?;
        if record.authority != self.record.authority
            || record.initialization != self.record.initialization
            || record.sequence != self.record.sequence
            || record.previous != self.record.previous
            || record.observed_at != self.record.observed_at
            || record.scope != self.record.scope
            || record.release != self.record.release
            || record.request != self.record.request
            || record.current_rows != self.record.current_rows
            || record.current_bytes != self.record.current_bytes
        {
            return Err(invalid(
                "native knowledge join differs from its complete proposed source",
            ));
        }
        self.preview
            .verify_actual(&record.result, record.changes.as_slice())
            .map_err(invalid)?;
        crate::security_state::verify_native_join_snapshot(tx, &record.authority, &record.result)
            .map_err(invalid)
    }

    pub(super) fn verify_encoding(
        &self,
        root: &[u8],
        chunks: &[crate::admission_operation_store::knowledge::encoding::chunks::StagedKnowledgeEncodingChunk],
    ) -> Result<(), AdmissionOperationStoreError> {
        let Some((_, _, expected)) = self.protected_rows.first() else {
            return Err(invalid("native knowledge preview lacks its root"));
        };
        if root.len() != expected.len() || chunks.len() + 1 != self.protected_rows.len() {
            return Err(invalid(
                "native knowledge encoding differs from its proposed physical shape",
            ));
        }
        for (actual, (key, scope, payload)) in chunks.iter().zip(&self.protected_rows[1..]) {
            if actual.key() != key
                || actual.scope() != scope
                || actual.payload().len() != payload.len()
            {
                return Err(invalid(
                    "native knowledge chunk differs from its proposed physical shape",
                ));
            }
        }
        Ok(())
    }

    pub(in crate::admission_operation_store) fn native_catalog_fingerprint(&self) -> &str {
        &self.native_catalog_fingerprint
    }
    pub(in crate::admission_operation_store) fn native_write_shapes(
        &self,
    ) -> &[NativeWriteShapeData] {
        &self.native_shapes
    }
    pub(in crate::admission_operation_store) fn protected_commands(
        &self,
    ) -> &[ProtectedCommandLiabilityPlan] {
        &self.protected_commands
    }
    pub(in crate::admission_operation_store) fn protected_journal_rows(
        &self,
    ) -> &[(String, String, Vec<u8>)] {
        &self.protected_rows
    }
    pub(in crate::admission_operation_store) fn journal_authority_id(&self) -> &str {
        self.initialized.authority.as_str()
    }
    pub(in crate::admission_operation_store) fn journal_records(&self) -> u64 {
        1
    }
    pub(in crate::admission_operation_store) fn journal_bytes(&self) -> u64 {
        self.journal_bytes
    }
}

pub(super) fn apply_totals(
    (mut rows, mut bytes): (u64, u64),
    changes: &[NativeRowChange],
) -> Result<(u64, u64), AdmissionOperationStoreError> {
    for change in changes {
        if let Some(before) = &change.before {
            rows = rows
                .checked_sub(1)
                .ok_or_else(|| invalid("native knowledge row underflow"))?;
            bytes = bytes
                .checked_sub(u64::try_from(before.len()).map_err(invalid)?)
                .ok_or_else(|| invalid("native knowledge bytes underflow"))?;
        }
        if let Some(after) = &change.after {
            rows = rows
                .checked_add(1)
                .ok_or_else(|| invalid("native knowledge row overflow"))?;
            bytes = bytes
                .checked_add(u64::try_from(after.len()).map_err(invalid)?)
                .ok_or_else(|| invalid("native knowledge bytes overflow"))?;
        }
    }
    if rows > 65_536 || bytes > 67_108_864 {
        return Err(invalid("native knowledge current inventory exceeds bounds"));
    }
    Ok((rows, bytes))
}

fn write_shapes(
    authority: &str,
    changes: &[NativeRowChange],
) -> Result<Vec<NativeWriteShapeData>, AdmissionOperationStoreError> {
    let mut shapes = BTreeMap::<(NativeWriteTableData, String), NativeWriteShapeData>::new();
    for change in changes {
        let table = NativeWriteTableData::from_source(&change.table)?;
        let after = change
            .after
            .as_deref()
            .ok_or_else(|| invalid("native join liability cannot delete rows"))?;
        let values =
            decode_retained_security_row(&change.table, after.as_bytes()).map_err(invalid)?;
        let columns = retained_security_columns(&change.table).map_err(invalid)?;
        let mut primary_key = vec![("security_authority_id", authority.into())];
        for name in table.source_keys() {
            let Some(Value::Text(value)) = columns
                .iter()
                .zip(&values)
                .find_map(|(column, value)| (*column == *name).then_some(value))
            else {
                return Err(invalid("native liability changed its primary-key layout"));
            };
            primary_key.push((*name, value.clone()));
        }
        let identity = sha256_hex(&chio_core::canonical_json_bytes(&primary_key).map_err(invalid)?);
        let maximum_after_record_bytes = row_footprint::record_bytes(authority, &values)?;
        let before_record_bytes = change
            .before
            .as_deref()
            .map(|before| {
                let before = decode_retained_security_row(&change.table, before.as_bytes())
                    .map_err(invalid)?;
                row_footprint::record_bytes(authority, &before)
            })
            .transpose()?;
        let maximum_record_bytes = maximum_after_record_bytes.max(before_record_bytes.unwrap_or(0));
        match shapes.entry((table, identity)) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(NativeWriteShapeData {
                    table,
                    primary_key,
                    existed: change.before.is_some(),
                    generation_only: table == NativeWriteTableData::FlowContexts
                        && change.before.is_some(),
                    before_record_bytes,
                    maximum_after_record_bytes,
                    maximum_record_bytes,
                    source_mutations: 1,
                });
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let shape = entry.get_mut();
                if shape.primary_key != primary_key || !shape.existed || change.before.is_none() {
                    return Err(invalid(
                        "native liability repeats an unsupported inserted row",
                    ));
                }
                shape.maximum_after_record_bytes = shape
                    .maximum_after_record_bytes
                    .max(maximum_after_record_bytes);
                shape.maximum_record_bytes = shape.maximum_record_bytes.max(maximum_record_bytes);
                shape.source_mutations = shape
                    .source_mutations
                    .checked_add(1)
                    .ok_or_else(|| invalid("native liability mutation count overflow"))?;
            }
        }
    }
    Ok(shapes.into_values().collect())
}

fn global_head(tx: &Connection) -> Result<(i64, String), AdmissionOperationStoreError> {
    tx.query_row("SELECT head_sequence,head_chain_digest FROM main.authority_global_commit_meta WHERE singleton=1", [], |row| Ok((row.get(0)?,row.get(1)?))).map_err(sqlite_error)
}
