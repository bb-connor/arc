//! Current inherited-scope influence projections fold inside the owning join.
//!
//! Warm observation reads only the bounded per-scope projections written by
//! the ordinary knowledge join itself; it never scans the retained history
//! bodies. Cold open verifies every stored projection against a fold
//! recomputed from the genuine immutable knowledge history, so a missing,
//! stale or forged projection fails closed instead of silently under- or
//! over-reporting influence.
use super::influence_slots::{
    authenticate_slot, authority_slot_prefix, source_slots, InfluenceScope, NativeInfluenceSlot,
    MAX_NATIVE_INFLUENCE_PAYLOAD_BYTES,
};
use super::*;
use chio_core::recovery::{knowledge_digest, RecoveryDigestDomain};
use chio_security_types::knowledge::ArtifactInfluenceV1;
use chio_security_types::ports::FlowStateKey;
use chio_security_types::recovery::{CanonicalPayloadDigest, SafeInteger};
use std::collections::BTreeSet;
use std::ops::Deref;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
enum ScopeHeadSchema {
    #[serde(rename = "chio.native-influence.scope-head.v1")]
    V1,
}

/// Decoded data cannot construct current custody or a phase allowance. The
/// revision is this slot's actual protected row version, and the source
/// sequence is the global knowledge join sequence whose influence was last
/// folded into the source chain. Both bind to real on-disk values.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeHead {
    schema: ScopeHeadSchema,
    native_authority: NativeSecurityAuthorityBindingV1,
    inherited_scope: InfluenceScope,
    revision: SafeInteger,
    source_sequence: SafeInteger,
    source_chain: CanonicalPayloadDigest,
    externally_influenced: bool,
    unknown: bool,
}

/// One projection mutation previewed by the join liability and then persisted
/// by the same owning transaction. The before payload anchors the fold base;
/// the after payload is the folded successor.
pub(in crate::admission_operation_store) struct ScopeHeadWrite {
    pub(super) slot: NativeInfluenceSlot,
    pub(super) before: Option<Vec<u8>>,
    pub(super) after: Vec<u8>,
}

impl ScopeHeadWrite {
    pub(in crate::admission_operation_store) fn record_key(&self) -> &str {
        self.slot.record_key()
    }

    pub(in crate::admission_operation_store) fn scope_key(&self) -> &str {
        self.slot.scope_key()
    }

    pub(in crate::admission_operation_store) fn before_payload(&self) -> Option<&[u8]> {
        self.before.as_deref()
    }

    pub(in crate::admission_operation_store) fn after_payload(&self) -> &[u8] {
        &self.after
    }
}

/// Genesis chain of one inherited scope. The writer and the cold verifier
/// derive it identically, so a projection cannot invent its own origin.
fn empty_source_chain(
    binding: &NativeSecurityAuthorityBindingV1,
    scope: &InfluenceScope,
) -> Result<CanonicalPayloadDigest, AdmissionOperationStoreError> {
    Ok(CanonicalPayloadDigest::from_bytes(
        knowledge_digest(
            RecoveryDigestDomain::KnowledgeInfluenceFold,
            &("native-influence-empty-scope-v1", binding, scope),
        )
        .map_err(invalid)?,
    ))
}

/// Fold one observed release influence into a scope's source chain.
fn fold_source_chain(
    binding: &NativeSecurityAuthorityBindingV1,
    scope: &InfluenceScope,
    previous: &CanonicalPayloadDigest,
    influence: &ArtifactInfluenceV1,
) -> Result<CanonicalPayloadDigest, AdmissionOperationStoreError> {
    Ok(CanonicalPayloadDigest::from_bytes(
        knowledge_digest(
            RecoveryDigestDomain::KnowledgeInfluenceFold,
            &(
                "native-influence-scope-fold-v1",
                binding,
                scope,
                previous,
                influence,
            ),
        )
        .map_err(invalid)?,
    ))
}

/// One fold step shared by the warm writer and the cold verifier: extend a
/// scope's source chain by one observed release influence. The chain links
/// through the slot's current head and the flags only ever accumulate; the
/// caller supplies the real next slot revision and the global source
/// sequence of this fold.
fn folded_head(
    binding: &NativeSecurityAuthorityBindingV1,
    scope: &InfluenceScope,
    base: Option<&ScopeHead>,
    influence: &ArtifactInfluenceV1,
    revision: SafeInteger,
    source_sequence: SafeInteger,
) -> Result<ScopeHead, AdmissionOperationStoreError> {
    let (source_chain, externally_influenced, unknown) = match base {
        None => (
            fold_source_chain(
                binding,
                scope,
                &empty_source_chain(binding, scope)?,
                influence,
            )?,
            influence.externally_influenced,
            influence.unknown,
        ),
        Some(head) => {
            if head.source_sequence.get() >= source_sequence.get() {
                return Err(invalid(
                    "influence projection regressed its source sequence",
                ));
            }
            (
                fold_source_chain(binding, scope, &head.source_chain, influence)?,
                head.externally_influenced | influence.externally_influenced,
                head.unknown | influence.unknown,
            )
        }
    };
    Ok(ScopeHead {
        schema: ScopeHeadSchema::V1,
        native_authority: binding.clone(),
        inherited_scope: scope.clone(),
        revision,
        source_sequence,
        source_chain,
        externally_influenced,
        unknown,
    })
}

/// The next protected row version of one slot from its current head.
fn next_slot_revision(
    head: Option<&ScopeHead>,
) -> Result<SafeInteger, AdmissionOperationStoreError> {
    let revision = match head {
        None => 1,
        Some(head) => head
            .revision
            .get()
            .checked_add(1)
            .filter(|revision| SafeInteger::new(*revision).is_ok())
            .ok_or_else(|| invalid("influence projection revision overflow"))?,
    };
    SafeInteger::new(revision).map_err(invalid)
}

/// Verify the protected framing of one projection row: ordinary custody,
/// exact slot scope, bounded payload and a matching source reference.
fn verify_scope_header(
    tx: &Connection,
    slot: &NativeInfluenceSlot,
    row: &protected::RawRecord,
    source: &protected::ProtectedSourceReference,
) -> Result<(), AdmissionOperationStoreError> {
    let ordinary: bool = tx
        .query_row(
            "SELECT native_namespace IS NULL AND native_request IS NULL
         FROM admission_operation_recovery_records WHERE record_key=?1",
            [slot.record_key()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if row.kind != "command"
        || row.scope != slot.scope_key()
        || row.payload.is_empty()
        || row.payload.len() > slot.maximum_payload_bytes()
        || source.kind() != "command"
        || source.scope_key() != slot.scope_key()
        || source.version() != row.version
        || !ordinary
    {
        return Err(invalid("current influence head changed protected framing"));
    }
    Ok(())
}

/// Load and authenticate one current scope projection. Absence is genuine
/// only when no join ever wrote the scope; the writer creates the row in the
/// same transaction as its first relevant join.
fn load_scope_head(
    tx: &Connection,
    binding: &NativeSecurityAuthorityBindingV1,
    slot: &NativeInfluenceSlot,
) -> Result<Option<ScopeHead>, AdmissionOperationStoreError> {
    let Some(row) = protected::raw_checked(tx, slot.record_key())? else {
        return Ok(None);
    };
    let source = protected::source_reference(tx, slot.record_key())?;
    verify_scope_header(tx, slot, &row, &source)?;
    let head: ScopeHead = protected::decode(&row.payload)?;
    if head.native_authority != *binding
        || head.inherited_scope != *slot.inherited_scope()
        || head.revision.get() != row.version
    {
        return Err(invalid("current influence head changed its exact source"));
    }
    Ok(Some(head))
}

/// Preview the projection mutations of one ordinary knowledge join: fold the
/// observed release influence into each of the key's inherited scopes. The
/// revision is the slot's actual next protected row version; the source
/// sequence is this join's global sequence. The owning liability verifies the
/// fold base before the join and the exact written payloads after it, inside
/// the same transaction.
pub(super) fn preview_scope_head_writes(
    tx: &Connection,
    binding: &NativeSecurityAuthorityBindingV1,
    key: &FlowStateKey,
    influence: &ArtifactInfluenceV1,
    sequence: u64,
) -> Result<Vec<ScopeHeadWrite>, AdmissionOperationStoreError> {
    let slots = source_slots(binding, key)?;
    let source_sequence = SafeInteger::new(sequence).map_err(invalid)?;
    let mut writes = Vec::with_capacity(slots.len());
    for slot in slots {
        let scope = slot.inherited_scope();
        let previous = load_scope_head(tx, binding, &slot)?;
        let head = folded_head(
            binding,
            scope,
            previous.as_ref(),
            influence,
            next_slot_revision(previous.as_ref())?,
            source_sequence,
        )?;
        let after = protected::encode(&head)?;
        if after.len() > slot.maximum_payload_bytes() {
            return Err(invalid("influence projection exceeds its slot bound"));
        }
        writes.push(ScopeHeadWrite {
            slot,
            before: previous.map(|head| protected::encode(&head)).transpose()?,
            after,
        });
    }
    Ok(writes)
}

/// One verified successor of a native influence head.
pub(in crate::admission_operation_store) struct NativeInfluenceHeadWrite {
    key: String,
    scope: String,
    payload: Vec<u8>,
    expected: Option<Vec<u8>>,
    inherited_scope: InfluenceScope,
}

impl NativeInfluenceHeadWrite {
    pub(in crate::admission_operation_store) fn key(&self) -> &str {
        &self.key
    }
    pub(in crate::admission_operation_store) fn scope(&self) -> &str {
        &self.scope
    }
    pub(in crate::admission_operation_store) fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// The inherited-scope head writes of one native knowledge join, minted only
/// from that join's previewed projection writes in its own transaction.
pub(in crate::admission_operation_store) struct VerifiedNativeInfluenceHeads<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    binding: NativeSecurityAuthorityBindingV1,
    writes: Vec<NativeInfluenceHeadWrite>,
}

impl<'tx, 'conn> VerifiedNativeInfluenceHeads<'tx, 'conn> {
    fn from_preview(
        transaction: &'tx Transaction<'conn>,
        binding: &NativeSecurityAuthorityBindingV1,
        writes: &[ScopeHeadWrite],
    ) -> Self {
        Self {
            transaction,
            binding: binding.clone(),
            writes: writes
                .iter()
                .map(|write| NativeInfluenceHeadWrite {
                    key: write.record_key().to_owned(),
                    scope: write.scope_key().to_owned(),
                    payload: write.after.clone(),
                    expected: write.before.clone(),
                    inherited_scope: write.slot.inherited_scope().clone(),
                })
                .collect(),
        }
    }

    pub(in crate::admission_operation_store) fn writes(&self) -> &[NativeInfluenceHeadWrite] {
        &self.writes
    }

    /// Same writer; one to three distinct slots; each is this authority's
    /// exact slot for its inherited scope with an existing flow-state row and
    /// a bounded payload, and its current head is exactly the previewed base.
    pub(in crate::admission_operation_store) fn verify(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq::<Connection>(Deref::deref(self.transaction), Deref::deref(tx))
            || self.writes.is_empty()
            || self.writes.len() > 3
            || self
                .writes
                .iter()
                .map(|write| write.key.as_str())
                .collect::<BTreeSet<_>>()
                .len()
                != self.writes.len()
        {
            return Err(invalid(
                "native influence heads changed their writer or shape",
            ));
        }
        let authority = self.binding.security_authority_id().as_str();
        let prefix = authority_slot_prefix(authority);
        for write in &self.writes {
            authenticate_slot(
                &write.key,
                &write.scope,
                &self.binding,
                &write.inherited_scope,
            )?;
            if !write.key.starts_with(&prefix)
                || write.payload.is_empty()
                || write.payload.len() > MAX_NATIVE_INFLUENCE_PAYLOAD_BYTES
                || !write.inherited_scope.flow_row_exists(tx, authority)?
            {
                return Err(invalid(
                    "native influence head lacks its exact flow-state slot",
                ));
            }
            let unchanged = match (&write.expected, protected::raw_checked(tx, &write.key)?) {
                (Some(before), Some(row)) => row.payload == *before,
                (None, None) => true,
                _ => false,
            };
            if !unchanged {
                return Err(invalid("native influence head changed its fold base"));
            }
        }
        Ok(())
    }
}

/// Persist the previewed projection mutations through the closed native
/// influence writer, inside the owning join transaction. Each slot is bound to
/// its existing flow-state row and admitted by the physical intake band.
pub(super) fn persist_scope_head_writes(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    binding: &NativeSecurityAuthorityBindingV1,
    writes: &[ScopeHeadWrite],
) -> Result<(), AdmissionOperationStoreError> {
    let heads = VerifiedNativeInfluenceHeads::from_preview(tx, binding, writes);
    protected::persist_native_influence_heads(tx, owner, &heads)
}

/// Verify the persisted projections equal the previewed successors exactly,
/// including their actual slot revision and authenticated slot identity.
pub(super) fn verify_scope_head_writes(
    tx: &Connection,
    binding: &NativeSecurityAuthorityBindingV1,
    writes: &[ScopeHeadWrite],
) -> Result<(), AdmissionOperationStoreError> {
    for write in writes {
        let row = protected::raw_checked(tx, write.record_key())?
            .ok_or_else(|| invalid("influence projection disappeared from its slot"))?;
        let source = protected::source_reference(tx, write.record_key())?;
        verify_scope_header(tx, &write.slot, &row, &source)?;
        let head: ScopeHead = protected::decode(&row.payload)?;
        if row.payload.as_slice() != write.after_payload() {
            return Err(invalid("influence projection differs from its preview"));
        }
        if head.revision.get() != row.version {
            return Err(invalid("influence projection changed its slot revision"));
        }
        authenticate_slot(
            write.record_key(),
            write.scope_key(),
            binding,
            &head.inherited_scope,
        )?;
    }
    Ok(())
}

/// Merge scope heads into one observation. The warm reader and the historical
/// reader share this, so both derive the identical commitment and flags.
fn observation_from_heads(
    heads: Vec<(&str, ScopeHead)>,
) -> Result<Option<ArtifactInfluenceV1>, AdmissionOperationStoreError> {
    if heads.is_empty() {
        return Ok(None);
    }
    let mut external = false;
    let mut unknown = false;
    let mut folded = Vec::with_capacity(heads.len());
    for (record_key, head) in heads {
        external |= head.externally_influenced;
        unknown |= head.unknown;
        // Only relevant scoped identities enter the framing digest. Current
        // global coverage and an Eligible Input are never folded into it.
        folded.push((
            record_key,
            head.revision,
            head.source_sequence,
            head.source_chain,
            head.externally_influenced,
            head.unknown,
        ));
    }
    Ok(Some(ArtifactInfluenceV1 {
        commitment: CanonicalPayloadDigest::from_bytes(
            knowledge_digest(RecoveryDigestDomain::KnowledgeObservedInfluence, &folded)
                .map_err(invalid)?,
        ),
        externally_influenced: external,
        unknown,
    }))
}

/// Bounded warm observation: read only this key's current inherited-scope
/// projections. Each read is charged before it runs, so an exhausted budget
/// decodes nothing. No retained history body is loaded here.
pub(super) fn observe_current(
    tx: &Connection,
    binding: &NativeSecurityAuthorityBindingV1,
    key: &FlowStateKey,
    budget: &mut chio_semantic_contracts::VerificationBudget,
) -> Result<Option<ArtifactInfluenceV1>, AdmissionOperationStoreError> {
    let slots = source_slots(binding, key)?;
    let mut heads = Vec::with_capacity(slots.len());
    for slot in &slots {
        budget.charge(1).map_err(invalid)?;
        #[cfg(feature = "admission-test-support")]
        read_work_test_support::current_projection();
        let Some(head) = load_scope_head(tx, binding, slot)? else {
            // No join ever wrote this scope: it contributes nothing. The
            // writer creates the row in the same transaction as its first
            // relevant join, so absence is genuine absence.
            continue;
        };
        heads.push((slot.record_key(), head));
    }
    observation_from_heads(heads)
}

/// The exact scope-head versions one refused Input observed before its join.
/// Past versions keep no payload, only their immutable event digests, so the
/// owning origin retains the observed payloads as data. Each is authenticated
/// against the immutable history at the Input's cut; decoding it grants no
/// current custody.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store) struct RetainedInfluenceHeads {
    heads: Vec<RetainedInfluenceHead>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedInfluenceHead {
    source: protected::HistoricalProtectedSourceData,
    head: ScopeHead,
}

/// The current heads of this key's inherited scopes, retained with their exact
/// protected source identity. Absent scopes are absent here and are checked
/// against the immutable history when read back.
pub(super) fn retain_current_heads(
    tx: &Connection,
    binding: &NativeSecurityAuthorityBindingV1,
    key: &FlowStateKey,
) -> Result<RetainedInfluenceHeads, AdmissionOperationStoreError> {
    let mut heads = Vec::new();
    for slot in source_slots(binding, key)? {
        let Some(head) = load_scope_head(tx, binding, &slot)? else {
            continue;
        };
        heads.push(RetainedInfluenceHead {
            source: protected::source_reference(tx, slot.record_key())?.historical_data()?,
            head,
        });
    }
    Ok(RetainedInfluenceHeads { heads })
}

/// The observation a key had at a historical cut, from retained heads whose
/// exact payloads are authenticated against the immutable event history. A
/// scope without a retained head must have no protected version at the cut.
/// Work is charged like the warm reader: one unit per inherited scope.
pub(super) fn observe_retained_at_cut(
    tx: &Connection,
    binding: &NativeSecurityAuthorityBindingV1,
    key: &FlowStateKey,
    cut: u64,
    retained: &RetainedInfluenceHeads,
    budget: &mut chio_semantic_contracts::VerificationBudget,
) -> Result<Option<ArtifactInfluenceV1>, AdmissionOperationStoreError> {
    let slots = source_slots(binding, key)?;
    let mut heads = Vec::with_capacity(slots.len());
    for slot in &slots {
        budget.charge(1).map_err(invalid)?;
        let found = retained
            .heads
            .iter()
            .find(|entry| entry.source.record_key() == slot.record_key());
        let Some(entry) = found else {
            let written: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM main.authority_global_commits
                     WHERE projection_kind='recovery' AND projection_key=?1
                       AND commit_sequence<=?2)",
                    params![
                        slot.record_key(),
                        i64::try_from(cut).map_err(|_| invalid("influence cut exhausted"))?
                    ],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
            if written {
                return Err(invalid("retained influence heads omit a written scope"));
            }
            continue;
        };
        if entry.head.native_authority != *binding
            || entry.head.inherited_scope != *slot.inherited_scope()
            || !protected::matches_historical_source_payload_at_cut(
                tx,
                &entry.source,
                slot.record_key(),
                slot.scope_key(),
                "command",
                &protected::encode(&entry.head)?,
                cut,
            )?
        {
            return Err(invalid("retained influence head differs from its history"));
        }
        heads.push((slot.record_key(), entry.head.clone()));
    }
    if heads.len() != retained.heads.len() {
        return Err(invalid("retained influence heads have foreign entries"));
    }
    observation_from_heads(heads)
}

/// Verify current projections after the cold owner authenticates immutable
/// history. Work is bounded by that history, independently of the warm read
/// budget. Projections are checked, never rebuilt or accepted as source truth.
pub(in crate::admission_operation_store) fn verify_current_projections(
    tx: &Connection,
    binding: &NativeSecurityAuthorityBindingV1,
) -> Result<(), AdmissionOperationStoreError> {
    #[cfg(feature = "admission-test-support")]
    read_work_test_support::projection_recomputation();
    let has_records: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='admission_operation_recovery_records')",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if !has_records {
        return Ok(());
    }
    let authority = binding.security_authority_id().as_str();
    let mut expected = std::collections::BTreeMap::<String, ScopeHead>::new();
    for sequence in 1..=head(tx, authority)? {
        let record = load(tx, authority, sequence)?;
        for slot in source_slots(binding, &record.request.key)? {
            let base = expected.get(slot.record_key());
            let next = folded_head(
                binding,
                slot.inherited_scope(),
                base,
                &record.release.influence,
                next_slot_revision(base)?,
                SafeInteger::new(sequence).map_err(invalid)?,
            )?;
            expected.insert(slot.record_key().to_owned(), next);
        }
    }
    // One extra key detects excess custody without reading an unbounded
    // inventory. The prefix hashes the authority, so it cannot contain SQL
    // glob metacharacters or select another authority's rows.
    let limit = i64::try_from(expected.len()).map_err(invalid)? + 1;
    let mut statement = tx
        .prepare(
            "SELECT record_key FROM admission_operation_recovery_records
         WHERE record_key GLOB ?1 LIMIT ?2",
        )
        .map_err(sqlite_error)?;
    let keys = statement
        .query_map(
            params![format!("{}*", authority_slot_prefix(authority)), limit],
            |row| row.get::<_, String>(0),
        )
        .map_err(sqlite_error)?;
    for key in keys {
        let key = key.map_err(sqlite_error)?;
        let expected_head = expected
            .remove(&key)
            .ok_or_else(|| invalid("orphan influence projection has no genuine source sequence"))?;
        let slot = NativeInfluenceSlot::derive(binding, &expected_head.inherited_scope)?;
        let actual = load_scope_head(tx, binding, &slot)?
            .ok_or_else(|| invalid("influence projection disappeared from its slot"))?;
        if actual != expected_head {
            return Err(invalid(
                "influence projection differs from its genuine immutable history",
            ));
        }
        if !expected_head
            .inherited_scope
            .flow_row_exists(tx, authority)?
        {
            return Err(invalid("influence projection has no flow-state row"));
        }
    }
    if !expected.is_empty() {
        return Err(invalid(
            "genuine immutable history is missing its influence projection",
        ));
    }
    Ok(())
}
