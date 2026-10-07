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

pub(in crate::admission_operation_store) mod encoding;
mod release_source;
pub(in crate::admission_operation_store) use release_source::release_observation_source;

#[cfg(feature = "admission-test-support")]
mod encoding_test_support;
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
pub(in crate::admission_operation_store) fn observed_influence(
    tx: &Connection,
    authority: &str,
    key: &FlowStateKey,
) -> Result<Option<chio_security_types::knowledge::ArtifactInfluenceV1>, AdmissionOperationStoreError>
{
    use chio_core::recovery::{knowledge_digest, RecoveryDigestDomain};
    use chio_security_types::{knowledge::ArtifactInfluenceV1, recovery::CanonicalPayloadDigest};
    let mut observed = Vec::new();
    let mut external = false;
    let mut unknown = false;
    for sequence in 1..=head(tx, authority)? {
        let record = load(tx, authority, sequence)?;
        let other = &record.request.key;
        // Principal and session rows share principal/epoch ownership; lineage
        // confidentiality survives a new principal or isolation epoch.
        if other.tenant_id == key.tenant_id
            && (other.lineage_id == key.lineage_id
                || (other.isolation_epoch_id == key.isolation_epoch_id
                    && other.principal_id == key.principal_id))
        {
            external |= record.release.influence.externally_influenced;
            unknown |= record.release.influence.unknown;
            observed.push(record.release.influence);
        }
    }
    if observed.is_empty() {
        return Ok(None);
    }
    Ok(Some(ArtifactInfluenceV1 {
        commitment: CanonicalPayloadDigest::from_bytes(
            knowledge_digest(RecoveryDigestDomain::KnowledgeObservedInfluence, &observed)
                .map_err(invalid)?,
        ),
        externally_influenced: external,
        unknown,
    }))
}
impl Record {
    pub(in crate::admission_operation_store) fn validate(
        &self,
    ) -> Result<(), AdmissionOperationStoreError> {
        let label = &self.release.source_label;
        let recipient = &self.release.recipient;
        if self.sequence == 0
            || self.current_rows > 65_536
            || self.current_bytes > 67_108_864
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
pub(in crate::admission_operation_store) fn head(
    tx: &Connection,
    authority: &str,
) -> Result<u64, AdmissionOperationStoreError> {
    let exists:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='admission_operation_recovery_records')",[],|row|row.get(0)).map_err(sqlite_error)?;
    if !exists {
        return Ok(0);
    }
    let count: i64 = tx
        .query_row(
            "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB ?1",
            [format!("{}*", prefix(authority))],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if !(0..=4096).contains(&count) {
        return Err(invalid("knowledge history exhausted"));
    }
    u64::try_from(count).map_err(invalid)
}
pub(in crate::admission_operation_store) fn load_with_digest(
    tx: &Connection,
    authority: &str,
    sequence: u64,
) -> Result<(Record, String), AdmissionOperationStoreError> {
    let key = record_key(authority, sequence);
    let row = protected::raw_checked(tx, &key)?.ok_or_else(|| invalid("knowledge join absent"))?;
    // Require the latest event and exact authenticated global reference. An
    // older still-authentic record cannot replace its protected head.
    let source = protected::source_reference(tx, &key)?;
    let record = encoding::decode(tx, &key, row.version, &row.payload)?;
    let header_is_local: bool = tx
        .query_row(
            "SELECT native_namespace IS NULL AND native_request IS NULL
         FROM admission_operation_recovery_records WHERE record_key=?1",
            [&key],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if row.version != 1
        || source.version() != 1
        || row.kind != "command"
        || source.kind() != "command"
        || row.scope != protected::scope_key(&record.scope)?
        || source.scope_key() != row.scope
        || record.sequence != sequence
        || record.authority != authority
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
    let (mut rows, mut bytes) = history::ordered::latest_totals(&tx, &initialized)?;
    let sequence = head(&tx, authority)?
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
    for change in &changes {
        if let Some(before) = &change.before {
            rows = rows
                .checked_sub(1)
                .ok_or_else(|| invalid("knowledge row underflow"))?;
            bytes = bytes
                .checked_sub(before.len() as u64)
                .ok_or_else(|| invalid("knowledge byte underflow"))?;
        }
        if let Some(after) = &change.after {
            rows = rows
                .checked_add(1)
                .ok_or_else(|| invalid("knowledge row overflow"))?;
            bytes = bytes
                .checked_add(after.len() as u64)
                .ok_or_else(|| invalid("knowledge byte overflow"))?;
        }
    }
    release.source_label = request.principal_join.clone();
    release.observation_generation =
        chio_security_types::recovery::SafeInteger::new(result.context_generation)
            .map_err(invalid)?;
    let record = Record {
        authority: authority.to_owned(),
        initialization: initialized.digest,
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
    let write = encoding::prepare(&tx, &record)?;
    #[cfg(feature = "admission-test-support")]
    encoding_test_support::observe_wire(&record, write.root_payload());
    let (_source, _delta) = protected::persist_knowledge_encoding(&tx, owner, write)?;
    history::ordered::validate_history_bounds(&tx, authority)?;
    Ok((tx, release))
}
