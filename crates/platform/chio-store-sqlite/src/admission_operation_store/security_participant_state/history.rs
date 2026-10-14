//! Historical command custody and row deltas, rooted in immutable hydration.
use super::*;
use crate::security_state::NativeRowChange;
use chio_kernel::admission_operation::{
    NativeSecurityFlowJoinRecordV1, NativeSecurityInputJoinRecordV1,
    NativeSecurityInputJoinRequestV1, PersistedAdmissionOperationV1,
};
use chio_kernel::SecurityInvocationContext;
use chio_security_types::ports::{BoundedVec, FlowJoinRequest, FlowStateSnapshot};

mod lease;
pub(super) mod ordered;
mod rows;
pub(super) mod segments;
pub(super) use rows::verify_rows;

pub(super) const MUTATION: &str = "join_security_participant_flow";
const FORMAT: &str = "chio.native-security-flow-join.v1";
const INPUT_FORMAT: &str = "chio.native-security-flow-join.v2";
const FATE_FORMAT: &str = "chio.native-security-flow-join.v3";
const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;
const MAX_ORIGIN_BYTES: usize = 16 * 1024 * 1024;

/// The classified Input fate every Input join of this format retains. Serde
/// omission only preserves older bytes; an absent fate is never read as Eligible.
#[derive(Serialize, Deserialize)]
#[serde(tag = "fate", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum NativeInputFateV1 {
    /// No selected semantic scope, or the verified assessment was Eligible.
    Eligible,
    /// The exact canonical refused-Input origin from the writing transaction.
    Refused { origin: serde_json::Value },
}

/// What authenticated history proves about one Input join's fate. A record
/// written before fates were retained is Unproved: it is never re-verified
/// against later sources and never becomes Eligible.
pub(super) use chio_kernel::admission_operation::NativeSecurityInputFateV1 as HistoricalInputFate;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LeaseHistory {
    claimant: AdmissionIdentifier,
    lease_id: AdmissionIdentifier,
    expires_at: u64,
    pub fence: StoreMutationFence,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub schema: String,
    pub authority: AdmissionIdentifier,
    pub sequence: u64,
    pub initialization: String,
    pub previous: String,
    pub operation: PersistedAdmissionOperationV1,
    pub lease: LeaseHistory,
    pub context: SecurityInvocationContext,
    // Preserve v1 canonical bytes. V2 explicitly retains classified-input intent;
    // neither a transition prefix nor a resolved command can infer that intent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<NativeSecurityInputJoinRequestV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_fate: Option<NativeInputFateV1>,
    pub request: FlowJoinRequest,
    pub result: FlowStateSnapshot,
    pub observed_at: u64,
    pub decision_at: u64,
    pub changes: BoundedVec<NativeRowChange, 4096>,
    pub current_rows: u64,
    pub current_bytes: u64,
}

impl LeaseHistory {
    pub(super) fn new(lease: &AdmissionRecoveryLease) -> Self {
        Self {
            claimant: lease.claimant_id().clone(),
            lease_id: lease.coordinator_lease_id().clone(),
            expires_at: lease.expires_at_unix_ms(),
            fence: lease.store_fence().clone(),
        }
    }
}

impl Record {
    pub(super) fn join_record(
        &self,
        initialized: &SecurityParticipantStateInitialization,
    ) -> Result<NativeSecurityFlowJoinRecordV1, AdmissionOperationStoreError> {
        if self.authority != initialized.authority || self.initialization != initialized.digest {
            return Err(invalid("native join initialization differs from history"));
        }
        let operation = AdmissionOperationV1::from_persisted(self.operation.clone())?;
        Ok(NativeSecurityFlowJoinRecordV1 {
            binding: initialized.admission_binding()?,
            operation_id: operation.binding().operation_id().clone(),
            mutation_digest: AdmissionDigest::try_new("native_mutation_digest", self.digest()?)?,
            command: self.request.clone(),
            snapshot: self.result.clone(),
        })
    }

    pub(super) fn input_record(
        &self,
        initialized: &SecurityParticipantStateInitialization,
    ) -> Result<NativeSecurityInputJoinRecordV1, AdmissionOperationStoreError> {
        let record = NativeSecurityInputJoinRecordV1 {
            input: self
                .input
                .clone()
                .ok_or_else(|| invalid("raw native join is not an input join"))?,
            join: self.join_record(initialized)?,
            fate: self.input_fate(),
        };
        record.validate()?;
        Ok(record)
    }

    pub(super) fn input_fate(&self) -> HistoricalInputFate {
        match (self.schema.as_str(), &self.input_fate) {
            (FATE_FORMAT, Some(NativeInputFateV1::Eligible)) => HistoricalInputFate::Eligible,
            (FATE_FORMAT, Some(NativeInputFateV1::Refused { .. })) => HistoricalInputFate::Refused,
            _ => HistoricalInputFate::Unproved,
        }
    }

    fn authority_binding(
        &self,
    ) -> Result<
        chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1,
        AdmissionOperationStoreError,
    > {
        Ok(
            chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1::new(
                AdmissionIdentifier::try_new(
                    "native_store_uuid",
                    self.lease.fence.store_uuid.clone(),
                )?,
                self.authority.clone(),
                AdmissionDigest::try_new(
                    "native_initialization_digest",
                    self.initialization.clone(),
                )?,
            ),
        )
    }

    /// The flow state before this join, from the captured before-images and
    /// the unchanged rows of the result. Never inferred as Bottom.
    pub(super) fn before_snapshot(
        &self,
    ) -> Result<FlowStateSnapshot, AdmissionOperationStoreError> {
        NativeRowChange::predecessor_snapshot_for_native_flow_join(
            &self.request,
            &self.result,
            self.changes.as_slice(),
        )
        .map_err(invalid)
    }

    pub(super) fn bytes(&self) -> Result<Vec<u8>, AdmissionOperationStoreError> {
        let bytes = canonical_json_bytes(self).map_err(invalid)?;
        if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
            return Err(invalid("native mutation record exceeds bounds"));
        }
        Ok(bytes)
    }

    pub(super) fn digest(&self) -> Result<String, AdmissionOperationStoreError> {
        let mut bytes = b"chio.native-security-mutation.commit.v1\0".to_vec();
        bytes.extend(self.bytes()?);
        Ok(sha256_hex(&bytes))
    }

    pub(super) fn insert(
        &self,
        connection: &Connection,
    ) -> Result<(), AdmissionOperationStoreError> {
        let operation = AdmissionOperationV1::from_persisted(self.operation.clone())?;
        connection.execute(
            "INSERT INTO security_participant_state_mutations
             (security_authority_id, sequence, operation_id, tenant_id, transition_id, canonical_record, mutation_digest, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![self.authority.as_str(), i64::try_from(self.sequence).map_err(invalid)?,
                operation.binding().operation_id().as_str(), self.request.key.tenant_id.as_str(),
                self.request.transition_id.as_str(), self.bytes()?, self.digest()?, i64::try_from(self.observed_at).map_err(invalid)?],
        ).map_err(sqlite_error)?;
        Ok(())
    }

    /// Structural and current-writer validation. A record that has not been
    /// appended has no retained global commit, so this is the only phase that
    /// can run before the append: at the pre-append writer check and at the
    /// in-flight projection-reference read. Every load of a retained record
    /// also runs `validate`, which adds the historical checks.
    pub(super) fn validate_structure(
        &self,
        connection: &Connection,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.validated_original(connection).map(|_| ())
    }

    /// Full validation of a retained record: structure plus, for a refused
    /// Input, the cold origin check against its actual retained global commit.
    pub(super) fn validate(
        &self,
        connection: &Connection,
    ) -> Result<(), AdmissionOperationStoreError> {
        let original = self.validated_original(connection)?;
        self.validate_retained_fate(connection, &original)
    }

    fn validated_original(
        &self,
        connection: &Connection,
    ) -> Result<
        chio_kernel::admission_operation::RetainedToolAdmissionRequestV1,
        AdmissionOperationStoreError,
    > {
        let operation = AdmissionOperationV1::from_persisted(self.operation.clone())?;
        let original = super::mutations::require_request(
            connection,
            &operation,
            &self.context,
            &self.request.key,
        )?;
        match (self.schema.as_str(), &self.input, &self.input_fate) {
            (FORMAT, None, None) => (),
            (INPUT_FORMAT, Some(input), None) | (FATE_FORMAT, Some(input), Some(_)) => {
                // Only raw v1 history may predate original native selection.
                // A new-format event must retain the writer's original custody
                // requirements when reopened, not just its resolved labels.
                if original.native_security_authority_binding().is_none()
                    || original.authority_profile().is_none()
                {
                    return Err(invalid(
                        "native input history lacks original authority custody",
                    ));
                }
                input.validate_resolution(
                    operation.binding().operation_id(),
                    &self.request,
                    &self.result,
                )?;
            }
            _ => return Err(invalid("native join schema and command family differ")),
        }
        if let Some(NativeInputFateV1::Refused { origin }) = &self.input_fate {
            if !origin.is_object()
                || canonical_json_bytes(origin).map_err(invalid)?.len() > MAX_ORIGIN_BYTES
            {
                return Err(invalid("native refused Input origin is not bounded data"));
            }
        }
        if original.native_security_authority_binding().is_some() {
            // These are historical equality checks, not present authority.
            // Initialization-chain and lease-commit verification independently
            // bind these fields to their original anchored records.
            original.validate_native_security_authority(&self.authority_binding()?)?;
        }
        super::super::schema::validate_trusted_time(self.observed_at, "native mutation time")?;
        super::super::schema::validate_trusted_time(self.decision_at, "native decision time")?;
        for change in self.changes.as_slice() {
            change.validate_flow_join(&self.request).map_err(invalid)?;
        }
        if self.observed_at.abs_diff(self.decision_at) > MAX_TRUSTED_CLOCK_SKEW_MS
            || self.sequence < 2
            || self.sequence > 9_007_199_254_740_991
            || self.result.key != self.request.key
            || self.changes.is_empty()
            || self.changes.as_slice().iter().any(|change| {
                change.after.is_none()
                    || !crate::security_state::is_native_flow_join_table(&change.table)
            })
            || self.result.context_generation == 0
            || self.result.context_generation > 9_007_199_254_740_991
            || self
                .result
                .principal_label
                .join_restrictions(&self.request.principal_join)
                .map_err(invalid)?
                != self.result.principal_label
            || self
                .result
                .lineage_label
                .join_restrictions(&self.request.lineage_join)
                .map_err(invalid)?
                != self.result.lineage_label
            || self
                .result
                .session_label
                .join_restrictions(&self.request.session_join)
                .map_err(invalid)?
                != self.result.session_label
        {
            return Err(invalid("native mutation command or result is malformed"));
        }
        self.lease.validate_operation(
            connection,
            &operation,
            self.observed_at,
            self.decision_at,
        )?;
        Ok(original)
    }

    /// Cold verification of a retained refused Input origin. Every field comes
    /// from authenticated native history: the retained request, this record
    /// and its binding, the before-state reconstructed from the captured
    /// before-images, this record's own retained global commit and its time.
    fn validate_retained_fate(
        &self,
        connection: &Connection,
        original: &chio_kernel::admission_operation::RetainedToolAdmissionRequestV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        let Some(NativeInputFateV1::Refused { origin }) = &self.input_fate else {
            return Ok(());
        };
        let input = self
            .input
            .as_ref()
            .ok_or_else(|| invalid("native refused Input lost its intent"))?;
        let operation = AdmissionOperationV1::from_persisted(self.operation.clone())?;
        let commit: i64 = connection
            .query_row(
                "SELECT commit_sequence FROM authority_global_commits
                 WHERE projection_kind = ?1 AND projection_key = ?2 AND projection_sequence = ?3
                   AND mutation_kind = ?4 AND projection_reference_digest = ?5",
                params![
                    PROJECTION_KIND,
                    self.authority.as_str(),
                    i64::try_from(self.sequence).map_err(invalid)?,
                    MUTATION,
                    self.digest()?
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?
            .ok_or_else(|| invalid("native refused Input lacks its retained global commit"))?;
        let canonical = canonical_json_bytes(origin).map_err(invalid)?;
        let before = self.before_snapshot()?;
        let origin = super::super::semantic::validate_historical_semantic_refused_input_origin(
            connection,
            &canonical,
            super::super::semantic::HistoricalSemanticRefusedInputObservation {
                operation: &operation,
                original,
                native_authority: &self.authority_binding()?,
                input,
                before: &before,
                joined: &self.request,
                snapshot: &self.result,
                input_global_commit: u64::try_from(commit).map_err(invalid)?,
                observed_at_unix_ms: self.observed_at,
            },
        )?;
        // The refused source restriction is joined into every retained label.
        for label in [
            &self.result.principal_label,
            &self.result.lineage_label,
            &self.result.session_label,
        ] {
            if !origin.source_label().flows_to(label) {
                return Err(invalid("native refused Input taint was lowered"));
            }
        }
        Ok(())
    }
}

/// Every Input join this binary writes retains its fate; raw joins keep v1.
/// The default-off prior-writer fixture keeps the exact v2 bytes the previous
/// binary emitted, so regressions replay genuine retained history.
pub(super) fn format(input: bool, store_uuid: &str) -> String {
    if !input {
        FORMAT.into()
    } else if prior_input_format_selected(store_uuid) {
        INPUT_FORMAT.into()
    } else {
        FATE_FORMAT.into()
    }
}

/// The fate one Input join retains. The prior-writer fixture retains none,
/// exactly as the previous binary did; assessment and custody are unchanged.
pub(super) fn retained_input_fate(
    store_uuid: &str,
    fate: Option<NativeInputFateV1>,
) -> Option<NativeInputFateV1> {
    if fate.is_some() && prior_input_format_selected(store_uuid) {
        return None;
    }
    fate
}

#[cfg(feature = "admission-test-support")]
fn prior_input_format_selected(store_uuid: &str) -> bool {
    prior_input_format::selected(store_uuid).unwrap_or(false)
}

#[cfg(not(feature = "admission-test-support"))]
fn prior_input_format_selected(_store_uuid: &str) -> bool {
    false
}

/// Default-off producer for genuine prior-writer Input records. While one
/// store is selected, its Input joins retain exactly the bytes the previous
/// binary wrote: v2 schema, no retained fate. Refusal assessment, origin
/// authentication and every custody check stay active; request bytes cannot
/// select this fixture.
#[cfg(feature = "admission-test-support")]
mod prior_input_format {
    use super::*;
    use std::{
        collections::BTreeSet,
        sync::{Mutex, OnceLock},
    };

    fn selected_stores() -> &'static Mutex<BTreeSet<String>> {
        static STORES: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
        STORES.get_or_init(|| Mutex::new(BTreeSet::new()))
    }

    /// Scoped to one authority store, including its native worker threads.
    /// Dropping the guard restores current Input fate retention.
    pub struct PriorInputFormatGuard {
        store_uuid: String,
    }

    impl Drop for PriorInputFormatGuard {
        fn drop(&mut self) {
            // A poisoned registry leaves every later selection failing closed.
            if let Ok(mut selected) = selected_stores().lock() {
                selected.remove(&self.store_uuid);
            }
        }
    }

    pub(super) fn selected(store_uuid: &str) -> Result<bool, AdmissionOperationStoreError> {
        Ok(selected_stores()
            .lock()
            .map_err(|_| invalid("prior Input format fixture registry unavailable"))?
            .contains(store_uuid))
    }

    pub(super) fn select(
        store_uuid: &str,
    ) -> Result<PriorInputFormatGuard, AdmissionOperationStoreError> {
        let mut selected = selected_stores()
            .lock()
            .map_err(|_| invalid("prior Input format fixture registry unavailable"))?;
        if !selected.insert(store_uuid.to_owned()) {
            return Err(invalid("prior Input format fixture already selected"));
        }
        Ok(PriorInputFormatGuard {
            store_uuid: store_uuid.to_owned(),
        })
    }
}

impl SqliteAdmissionOperationStore {
    /// Selects genuine prior-writer Input records for this store only: v2
    /// schema, no retained fate, produced by the real writer. Refusal
    /// assessment and all custody checks stay active.
    #[cfg(feature = "admission-test-support")]
    #[must_use = "dropping the guard restores current Input fate retention"]
    pub fn retained_prior_input_writer_for_test(
        &self,
    ) -> Result<impl Drop + 'static, AdmissionOperationStoreError> {
        prior_input_format::select(self.serving_owner.fence.store_uuid.as_str())
    }
}

pub(super) fn load(
    connection: &Connection,
    authority: &str,
    sequence: u64,
) -> Result<Option<Record>, AdmissionOperationStoreError> {
    let Some(record) = decoded(connection, authority, sequence)? else {
        return Ok(None);
    };
    record.validate(connection)?;
    Ok(Some(record))
}

impl Record {
    /// The exact global commit this record's writer appended: projection, key,
    /// sequence, mutation kind, reference digest and writer fence.
    pub(super) fn require_own_commit(
        &self,
        connection: &Connection,
    ) -> Result<(), AdmissionOperationStoreError> {
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind = ?1
                 AND projection_key = ?2 AND projection_sequence = ?3 AND mutation_kind = ?4
                 AND projection_reference_digest = ?5 AND store_uuid = ?6
                 AND store_lease_id = ?7 AND store_owner_epoch = ?8",
                params![
                    PROJECTION_KIND,
                    self.authority.as_str(),
                    i64::try_from(self.sequence).map_err(invalid)?,
                    MUTATION,
                    self.digest()?,
                    self.lease.fence.store_uuid,
                    self.lease.fence.lease_id,
                    i64::try_from(self.lease.fence.owner_epoch).map_err(invalid)?
                ],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if count != 1 {
            return Err(invalid("native mutation lacks its exact global commit"));
        }
        Ok(())
    }
}

/// One fully validated record bound to its exact own global commit. This is
/// the per-record unit of the cold walk and of every warm history readback.
pub(super) fn load_committed(
    connection: &Connection,
    authority: &str,
    sequence: u64,
) -> Result<Option<Record>, AdmissionOperationStoreError> {
    let Some(record) = load(connection, authority, sequence)? else {
        return Ok(None);
    };
    record.require_own_commit(connection)?;
    Ok(Some(record))
}

/// The committed record of one operation, read through its unique index.
pub(super) fn load_committed_for_operation(
    connection: &Connection,
    operation: &AdmissionOperationId,
) -> Result<Option<Record>, AdmissionOperationStoreError> {
    let Some(record) = load_for_operation(connection, operation)? else {
        return Ok(None);
    };
    record.require_own_commit(connection)?;
    Ok(Some(record))
}

/// The in-flight projection-reference read of the record the current writer
/// just inserted. Its own global commit does not exist yet, so this phase
/// authenticates only the structural and current-writer fields; the
/// reference digest it yields is exactly what the append then commits.
/// Retained and cold readers use `load`, which still requires the record's
/// actual own global commit and origin proof.
pub(super) fn load_for_projection_reference(
    connection: &Connection,
    authority: &str,
    sequence: u64,
) -> Result<Option<Record>, AdmissionOperationStoreError> {
    let Some(record) = decoded(connection, authority, sequence)? else {
        return Ok(None);
    };
    record.validate_structure(connection)?;
    Ok(Some(record))
}

/// Bounded typed read of one record's exact committed bytes and row
/// metadata. Shared by every load phase; it grants no custody.
fn decoded(
    connection: &Connection,
    authority: &str,
    sequence: u64,
) -> Result<Option<Record>, AdmissionOperationStoreError> {
    // Never allocate untrusted relational text before bounding it. Read only
    // the bounded canonical artifact, then compare typed metadata in SQLite.
    let row: Option<Option<Vec<u8>>> = connection.query_row(
        "SELECT CASE WHEN typeof(canonical_record) = 'blob' AND length(canonical_record) BETWEEN 1 AND 16777216
         AND length(CAST(mutation_digest AS BLOB)) = 64
         AND length(CAST(operation_id AS BLOB)) BETWEEN 1 AND 512
         AND length(CAST(tenant_id AS BLOB)) BETWEEN 1 AND 512
         AND length(CAST(transition_id AS BLOB)) BETWEEN 1 AND 512
         THEN canonical_record END FROM security_participant_state_mutations
         WHERE security_authority_id = ?1 AND sequence = ?2",
        params![authority, i64::try_from(sequence).map_err(invalid)?],
        |row| row.get(0),
    ).optional().map_err(sqlite_error)?;
    let Some(bytes) = row else {
        return Ok(None);
    };
    let bytes = bytes.ok_or_else(|| invalid("native mutation record exceeds bounds"))?;
    let record: Record = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("native mutation record is not bounded typed data"))?;
    let operation = AdmissionOperationV1::from_persisted(record.operation.clone())?;
    if record.authority.as_str() != authority
        || record.sequence != sequence
        || record.bytes()? != bytes
    {
        return Err(invalid(
            "native mutation projection differs from canonical history",
        ));
    }
    let exact: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM security_participant_state_mutations
         WHERE security_authority_id = ?1 AND sequence = ?2 AND mutation_digest = ?3
           AND operation_id = ?4 AND tenant_id = ?5 AND transition_id = ?6 AND observed_at = ?7)",
            params![
                authority,
                i64::try_from(sequence).map_err(invalid)?,
                record.digest()?,
                operation.binding().operation_id().as_str(),
                record.request.key.tenant_id.as_str(),
                record.request.transition_id.as_str(),
                i64::try_from(record.observed_at).map_err(invalid)?
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if !exact {
        return Err(invalid(
            "native mutation metadata differs from canonical history",
        ));
    }
    Ok(Some(record))
}

/// Absolute last mutation sequence. The live tail above the latest seal is
/// contiguous and within the segment bounds; sealed segments are verified cold.
pub(super) fn head(
    connection: &Connection,
    authority: &str,
) -> Result<u64, AdmissionOperationStoreError> {
    segments::family_head(connection, segments::Family::Mutations, authority)
}

pub(super) fn load_for_operation(
    connection: &Connection,
    operation: &AdmissionOperationId,
) -> Result<Option<Record>, AdmissionOperationStoreError> {
    let located: Option<(Option<String>, i64)> = connection.query_row(
        "SELECT CASE WHEN length(CAST(security_authority_id AS BLOB)) BETWEEN 1 AND 512
         THEN security_authority_id END, sequence FROM security_participant_state_mutations WHERE operation_id = ?1",
        [operation.as_str()], |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional().map_err(sqlite_error)?;
    let Some((authority, sequence)) = located else {
        return Ok(None);
    };
    let authority = authority.ok_or_else(|| invalid("native mutation authority exceeds bounds"))?;
    let record = load(
        connection,
        &authority,
        u64::try_from(sequence).map_err(invalid)?,
    )?
    .ok_or_else(|| invalid("native mutation index has no record"))?;
    Ok(Some(record))
}
