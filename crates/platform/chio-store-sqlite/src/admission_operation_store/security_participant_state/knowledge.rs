//! Affine artifact observation in the same native flow rows and global order.
use super::super::recovery::storage as protected;
use super::*;
use crate::security_state::NativeRowChange;
use chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1;
use chio_security_types::ports::{
    BoundedVec, FlowJoinRequest, FlowStateKey, FlowStateSnapshot, RecordId,
};
use chio_security_types::{
    knowledge::ArtifactReleaseIntentV1, recovery::RecoveryScopeV1, InformationLabel,
};

mod current_authority;
pub(in crate::admission_operation_store) mod encoding;
mod imported_influence;
#[cfg(test)]
pub(in crate::admission_operation_store) use imported_influence::full_scan_commitment;
pub(crate) use imported_influence::publish_imported_influence_roots_at_startup;
pub(in crate::admission_operation_store) use imported_influence::{
    install_imported_scope_index, verify_imported_scope_index, VerifiedImportedInfluenceRoot,
};
mod influence_projection;
pub(in crate::admission_operation_store) use influence_projection::{
    RetainedInfluenceHeads, VerifiedNativeInfluenceHeads,
};
pub(in crate::admission_operation_store) mod influence_slots;
pub(in crate::admission_operation_store) mod liability;
pub(in crate::admission_operation_store) use current_authority::CurrentNativeInfluenceAuthority;
mod release_source;
pub(in crate::admission_operation_store) use release_source::release_observation_source;

/// Recompute projections during full-chain verification, after native and
/// recovery history have been authenticated. Warm initialization checks do
/// not invoke this fold.
pub(crate) fn verify_initialized_scope_projections(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let bindings = records::initialized_authority_bindings(connection)?;
    if bindings.is_empty() {
        return imported_influence::verify_imported_scope_index_coverage(connection, 0);
    }
    let indexed = schema::recorded_version(connection)? == schema::CURRENT_VERSION;
    let mut pending = 0_u64;
    for binding in &bindings {
        influence_projection::verify_current_projections(connection, binding)?;
        if !indexed {
            continue;
        }
        // The binding census already authenticated each complete sealed source.
        // Authenticate its initialization before rebuilding the expected index.
        let initialization = records::load_current_metadata(connection, binding)?;
        // A genuine historical hydration may await its startup root; it holds
        // no root or index custody, and every other root-less authority refuses.
        if imported_influence::historical_root_pending(connection, &initialization)? {
            pending += 1;
            continue;
        }
        imported_influence::verify_imported_scope_index(connection, &initialization)?;
    }
    imported_influence::verify_imported_scope_index_coverage(
        connection,
        u64::try_from(bindings.len()).map_err(invalid)? - pending,
    )
}

#[cfg(feature = "admission-test-support")]
mod encoding_test_support;
#[cfg(feature = "admission-test-support")]
pub(in crate::admission_operation_store) mod read_work_test_support;
#[cfg(feature = "admission-test-support")]
pub(in crate::admission_operation_store) use encoding_test_support::observe_restore_record_encoding_bytes_fixture;

pub(crate) struct NativeKnowledgeJoinAuthority {
    authority: AdmissionIdentifier,
    request: FlowJoinRequest,
}
impl NativeKnowledgeJoinAuthority {
    pub(crate) fn authority(&self) -> &str {
        self.authority.as_str()
    }
    pub(crate) fn request(&self) -> &FlowJoinRequest {
        &self.request
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store) struct Record {
    pub authority: String,
    pub initialization: String,
    pub sequence: u64,
    pub previous: String,
    pub observed_at: u64,
    pub scope: RecoveryScopeV1,
    pub release: ArtifactReleaseIntentV1,
    pub request: FlowJoinRequest,
    pub result: FlowStateSnapshot,
    pub changes: BoundedVec<NativeRowChange, 4096>,
    pub current_rows: u64,
    pub current_bytes: u64,
}

pub(in crate::admission_operation_store) fn prefix(authority: &str) -> String {
    format!("knowledge-join:{}:", sha256_hex(authority.as_bytes()))
}
fn record_key(authority: &str, sequence: u64) -> String {
    format!("{}{sequence:016}", prefix(authority))
}

/// Influence follows every native scope that can carry confidentiality. Reading
/// an older checkpoint never discards later artifact or model observations.
/// This charged entry is the only influence reader. The bounded warm
/// projection reader charges one unit before loading each of this key's
/// three current inherited-scope projections, so no knowledge-join history
/// body is decoded and the authority's join history size never prices this
/// read. The history bound stays with the join writer and the cold
/// projection verifier. The sealed pre-recovery source contributes
/// conservatively through the same entry. Its fixed proof work and each
/// matching scope's member count are charged before reading those members;
/// unrelated source history never consumes the caller's work budget.
pub(in crate::admission_operation_store) fn budgeted_observed_influence(
    tx: &Connection,
    binding: &NativeSecurityAuthorityBindingV1,
    key: &FlowStateKey,
    budget: &mut chio_semantic_contracts::VerificationBudget,
) -> Result<Option<chio_security_types::knowledge::ArtifactInfluenceV1>, AdmissionOperationStoreError>
{
    let native = influence_projection::observe_current(tx, binding, key, budget)?;
    let imported = imported_influence::observed(tx, binding, key, budget)?;
    merged_observed_influence(native, imported)
}

/// The scope heads a refused Input observes, retained as data with their
/// exact protected source identity for later historical authentication.
pub(in crate::admission_operation_store) fn retain_influence_heads(
    tx: &Connection,
    binding: &NativeSecurityAuthorityBindingV1,
    key: &FlowStateKey,
) -> Result<RetainedInfluenceHeads, AdmissionOperationStoreError> {
    influence_projection::retain_current_heads(tx, binding, key)
}

/// The same merged observation `budgeted_observed_influence` reported at a
/// historical cut. The native part is read from retained scope heads that are
/// authenticated against the immutable event history at that cut; the imported
/// part is the sealed pre-recovery source. Work is the warm reader's, one unit
/// per inherited scope plus the imported proof, never the retained history.
pub(in crate::admission_operation_store) fn observed_influence_at_cut(
    tx: &Connection,
    binding: &NativeSecurityAuthorityBindingV1,
    key: &FlowStateKey,
    cut: u64,
    retained: &RetainedInfluenceHeads,
    budget: &mut chio_semantic_contracts::VerificationBudget,
) -> Result<Option<chio_security_types::knowledge::ArtifactInfluenceV1>, AdmissionOperationStoreError>
{
    let native =
        influence_projection::observe_retained_at_cut(tx, binding, key, cut, retained, budget)?;
    let imported = imported_influence::observed(tx, binding, key, budget)?;
    merged_observed_influence(native, imported)
}

/// Union of the native and imported observations. Imported history only ever
/// adds unknown influence; it never grants a trusted external classification
/// and never reduces the native observation.
fn merged_observed_influence(
    native: Option<chio_security_types::knowledge::ArtifactInfluenceV1>,
    imported: Option<chio_security_types::knowledge::ArtifactInfluenceV1>,
) -> Result<Option<chio_security_types::knowledge::ArtifactInfluenceV1>, AdmissionOperationStoreError>
{
    use chio_core::recovery::{knowledge_digest, RecoveryDigestDomain};
    use chio_security_types::recovery::CanonicalPayloadDigest;
    Ok(match (native, imported) {
        (None, None) => None,
        (None, Some(imported)) => Some(imported),
        (Some(native), None) => Some(native),
        (Some(native), Some(imported)) => {
            Some(chio_security_types::knowledge::ArtifactInfluenceV1 {
                commitment: CanonicalPayloadDigest::from_bytes(
                    knowledge_digest(
                        RecoveryDigestDomain::KnowledgeObservedInfluence,
                        &(native.commitment, imported.commitment),
                    )
                    .map_err(invalid)?,
                ),
                externally_influenced: native.externally_influenced,
                unknown: native.unknown || imported.unknown,
            })
        }
    })
}
impl Record {
    pub(in crate::admission_operation_store) fn validate(
        &self,
    ) -> Result<(), AdmissionOperationStoreError> {
        let label = &self.release.source_label;
        let recipient = &self.release.recipient;
        if self.sequence == 0
            || self.scope != recipient.scope
            || self.scope != self.release.artifact.scope
            || !self.release.admitted_label.flows_to(label)
            || !self.release.admitted_label.flows_to(&recipient.clearance)
            || self.request.principal_join != *label
            || self.request.lineage_join != *label
            || self.request.session_join != *label
            || self.result.key != self.request.key
            || self.release.observation_generation.get() != self.result.context_generation
            || self.request.transition_id.as_str() != self.release.observation_transition.as_str()
            || recipient.principal != self.request.key.principal_id
            || recipient.runtime.as_str() != self.request.key.session_id.as_str()
            || recipient.scope.tenant_id.as_str() != self.request.key.tenant_id.as_str()
            || recipient.lineage.as_str() != self.request.key.lineage_id.as_str()
            || recipient.isolation_epoch.as_str() != self.request.key.isolation_epoch_id.as_str()
            || self.changes.is_empty()
        {
            return Err(invalid("knowledge journal binding"));
        }
        for change in self.changes.as_slice() {
            change.validate_flow_join(&self.request).map_err(invalid)?;
        }
        Ok(())
    }
}
/// Absolute last knowledge join sequence. At most 4096 joins form the live
/// tail above the latest native journal seal.
pub(in crate::admission_operation_store) fn head(
    tx: &Connection,
    authority: &str,
) -> Result<u64, AdmissionOperationStoreError> {
    history::segments::knowledge_head(tx, authority)
}
/// Sequence of the last knowledge join key. Only a proof minted by the join
/// writer, which authenticated the live segment in the same transaction,
/// reads the head this way.
pub(in crate::admission_operation_store) fn last_join_sequence(
    tx: &Connection,
    authority: &str,
) -> Result<u64, AdmissionOperationStoreError> {
    history::segments::knowledge_last(tx, authority)
}
pub(in crate::admission_operation_store) fn load_with_digest(
    tx: &Connection,
    authority: &str,
    sequence: u64,
) -> Result<(Record, String), AdmissionOperationStoreError> {
    let (record, digest) = load_by_key(tx, &record_key(authority, sequence))?;
    if record.sequence != sequence || record.authority != authority {
        return Err(invalid("knowledge history changed exact protected custody"));
    }
    Ok((record, digest))
}

fn load_by_key(
    tx: &Connection,
    key: &str,
) -> Result<(Record, String), AdmissionOperationStoreError> {
    #[cfg(feature = "admission-test-support")]
    read_work_test_support::history_body();
    let row = protected::raw_checked(tx, key)?.ok_or_else(|| invalid("knowledge join absent"))?;
    // Require the latest event and exact authenticated global reference. An
    // older still-authentic record cannot replace its protected head.
    let source = protected::source_reference(tx, key)?;
    let record = encoding::decode(tx, key, row.version, &row.payload)?;
    let header_is_local: bool = tx
        .query_row(
            "SELECT native_namespace IS NULL AND native_request IS NULL
         FROM admission_operation_recovery_records WHERE record_key=?1",
            [key],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if row.version != 1
        || source.version() != 1
        || row.kind != "command"
        || source.kind() != "command"
        || row.scope != protected::scope_key(&record.scope)?
        || source.scope_key() != row.scope
        || key != record_key(&record.authority, record.sequence)
        || !header_is_local
    {
        return Err(invalid("knowledge history changed exact protected custody"));
    }
    record.validate()?;
    // Legacy bodies keep their original canonical hash preimages. Compact
    // records bind their validated immutable wire bytes, without subjecting
    // the expanded labels to the smaller protected-record encoder.
    let digest = sha256_hex(&row.payload);
    Ok((record, digest))
}

pub(in crate::admission_operation_store) fn load(
    tx: &Connection,
    authority: &str,
    sequence: u64,
) -> Result<Record, AdmissionOperationStoreError> {
    load_with_digest(tx, authority, sequence).map(|(record, _)| record)
}

pub(in crate::admission_operation_store) struct KnowledgeJoin<'a> {
    pub binding: &'a NativeSecurityAuthorityBindingV1,
    pub key: &'a FlowStateKey,
    pub source: &'a InformationLabel,
    pub scope: &'a RecoveryScopeV1,
    pub release: ArtifactReleaseIntentV1,
    pub now: u64,
}
pub(in crate::admission_operation_store) fn join<'a>(
    tx: Transaction<'a>,
    owner: &SqliteServingOwner,
    input: KnowledgeJoin<'_>,
) -> Result<(Transaction<'a>, ArtifactReleaseIntentV1), AdmissionOperationStoreError> {
    let origin = owner
        .prepare_native_source_transaction(&tx)
        .map_err(map_owner_error)?;
    join_with_origin(tx, owner, &origin, input)
}

/// An enclosing source may have already appended independently authenticated
/// evidence. It retains its actual initial cut before those mutations.
pub(in crate::admission_operation_store) fn join_with_origin<'a>(
    tx: Transaction<'a>,
    owner: &SqliteServingOwner,
    origin: &crate::serving_owner::NativeSourceTransactionOrigin<'_>,
    input: KnowledgeJoin<'_>,
) -> Result<(Transaction<'a>, ArtifactReleaseIntentV1), AdmissionOperationStoreError> {
    let mut liability =
        liability::prepare_native_knowledge_join_liability(&tx, owner, origin, &input)?;
    liability.verify_before(&tx, owner)?;
    let KnowledgeJoin {
        binding,
        key,
        source,
        scope,
        mut release,
        now,
    } = input;
    let initialized = records::load_metadata(&tx, binding.security_authority_id().as_str())?
        .ok_or_else(|| invalid("knowledge native initialization absent"))?;
    if initialized.admission_binding()? != *binding {
        return Err(invalid("knowledge native binding"));
    }
    let authority = binding.security_authority_id().as_str();
    let transition = RecordId::new(release.observation_transition.as_str()).map_err(invalid)?;
    let request =
        crate::security_state::resolve_native_label_join(&tx, authority, key, source, &transition)
            .map_err(invalid)?;
    let totals = liability.latest_totals(&tx)?;
    let sequence = liability
        .knowledge_head(&tx)?
        .checked_add(1)
        .ok_or_else(|| invalid("knowledge sequence overflow"))?;
    let previous = if sequence == 1 {
        initialized.digest.clone()
    } else {
        load_with_digest(&tx, authority, sequence - 1)?.1
    };
    let (tx, result, changes) = crate::security_state::join_native_knowledge(
        tx,
        NativeKnowledgeJoinAuthority {
            authority: initialized.authority.clone(),
            request: request.clone(),
        },
    )
    .map_err(invalid)?;
    let (rows, bytes) = liability::apply_totals(totals, &changes)?;
    release.source_label = request.principal_join.clone();
    release.observation_generation =
        chio_security_types::recovery::SafeInteger::new(result.context_generation)
            .map_err(invalid)?;
    let record = Record {
        authority: authority.to_owned(),
        initialization: initialized.digest.clone(),
        sequence,
        previous,
        observed_at: now,
        scope: scope.clone(),
        release: release.clone(),
        request,
        result,
        changes: BoundedVec::new(changes).map_err(invalid)?,
        current_rows: rows,
        current_bytes: bytes,
    };
    record.validate()?;
    liability.verify_native_result(&tx, owner, &record)?;
    storage::require_tenant_live(&tx, authority, record.request.key.tenant_id.as_str())?;
    let write = encoding::prepare(&tx, &record)?;
    liability.verify_encoding(write.root_payload(), write.staged_chunks())?;
    #[cfg(feature = "admission-test-support")]
    read_work_test_support::knowledge_join_readback();
    #[cfg(feature = "admission-test-support")]
    encoding_test_support::observe_wire(&record, write.root_payload());
    let append = history::segments::Append::knowledge(&record, &write)?;
    let write = match liability.prepare_journal_append(&tx, owner, &append)? {
        history::segments::Boundary::Live => write,
        history::segments::Boundary::Sealed => {
            // The seal is a global commit after the head this encoding proof
            // captured. A fresh proof over the same record is prepared after
            // the seal and must encode exactly the admitted entry.
            let write = encoding::prepare(&tx, &record)?;
            liability.verify_encoding(write.root_payload(), write.staged_chunks())?;
            if history::segments::Append::knowledge(&record, &write)?.entry() != append.entry() {
                return Err(invalid(
                    "knowledge encoding changed across its journal seal",
                ));
            }
            write
        }
    };
    let (_source, _delta) = protected::persist_knowledge_encoding(&tx, owner, write)?;
    liability.appended(&tx, &append)?;
    // The same owning transaction folds this observation into its three
    // current inherited-scope projections. The liability previewed the exact
    // mutations and verifies the persisted rows against them, so a warm read
    // never rebuilds this fold from history.
    let projections = liability.projection_writes();
    influence_projection::persist_scope_head_writes(&tx, owner, binding, projections)?;
    influence_projection::verify_scope_head_writes(&tx, binding, projections)?;
    Ok((tx, release))
}
