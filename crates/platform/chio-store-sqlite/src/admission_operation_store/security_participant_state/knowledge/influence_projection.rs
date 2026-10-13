//! Current source identity is separate from the owner's authenticated prefix.
use super::influence_slots::{source_slots, InfluenceScope, NativeInfluenceSlot};
use super::*;
use chio_core::recovery::{knowledge_digest, RecoveryDigestDomain};
use chio_security_types::knowledge::ArtifactInfluenceV1;
use chio_security_types::recovery::{CanonicalPayloadDigest, SafeInteger};

#[derive(Serialize, Deserialize)]
enum ScopeHeadSchema {
    #[serde(rename = "chio.native-influence.scope-head.v1")]
    V1,
}

/// Decoded data cannot construct current custody or a phase allowance.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ScopeHead {
    schema: ScopeHeadSchema,
    native_authority: NativeSecurityAuthorityBindingV1,
    inherited_scope: InfluenceScope,
    revision: SafeInteger,
    observations: SafeInteger,
    source_chain: CanonicalPayloadDigest,
    externally_influenced: bool,
    unknown: bool,
}

#[derive(Serialize, Deserialize)]
enum CoverageSchema {
    #[serde(rename = "chio.native-influence.authority-head.v1")]
    V1,
}

/// The source catalog's census and folded provenance are independently bound.
/// Advancing lifecycle coverage does not alter any scoped provenance digest.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthorityHead {
    schema: CoverageSchema,
    native_authority: NativeSecurityAuthorityBindingV1,
    revision: SafeInteger,
    initialization_fingerprint: String,
    current_source_catalog: CanonicalPayloadDigest,
    catalog_global_sequence: SafeInteger,
    observations: SafeInteger,
}

struct VerifiedAuthorityCoverage {
    relevant_observations: u64,
}

pub(super) fn observe_current(
    custody: &CurrentNativeInfluenceAuthority<'_, '_, '_>,
    key: &FlowStateKey,
) -> Result<Option<ArtifactInfluenceV1>, AdmissionOperationStoreError> {
    custody.verify()?;
    let binding = custody.initialization().admission_binding()?;
    let [principal, lineage, session, authority] = source_slots(custody.owner(), &binding, key)?;
    let coverage = authenticate_coverage(custody, &binding, &authority)?;
    let mut folded = Vec::with_capacity(3);
    let mut external = false;
    let mut unknown = false;
    for slot in [&principal, &lineage, &session] {
        #[cfg(feature = "admission-test-support")]
        read_work_test_support::current_projection();
        let Some(row) = protected::raw_checked(custody.transaction(), slot.record_key())? else {
            continue;
        };
        let source = protected::source_reference(custody.transaction(), slot.record_key())?;
        verify_header(custody.transaction(), slot, &row, &source)?;
        let head: ScopeHead = protected::decode(&row.payload)?;
        if head.native_authority != binding
            || Some(&head.inherited_scope) != slot.inherited_scope()
            || head.revision.get() != row.version
            || head.observations.get() > coverage.relevant_observations
            || source.global_commit_sequence() > custody.current_global_sequence()
        {
            return Err(invalid("current influence head changed its exact source"));
        }
        if head.observations.get() == 0 {
            if head.externally_influenced
                || head.unknown
                || head.source_chain != empty_source_chain(&binding, &head.inherited_scope)?
            {
                return Err(invalid("empty influence metadata changed its source"));
            }
            // An admitted operation can own future fixed-header slots before
            // any relevant observation exists. Their existence is not a source
            // observation and cannot change the action's framing identity.
            continue;
        }
        external |= head.externally_influenced;
        unknown |= head.unknown;
        // Only relevant scoped identities enter the framing digest. Current
        // global coverage and an Eligible Input are never folded into it.
        folded.push((
            slot.record_key(),
            head.observations,
            head.source_chain,
            head.externally_influenced,
            head.unknown,
        ));
    }
    if folded.is_empty() {
        return Ok(None);
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

fn authenticate_coverage(
    custody: &CurrentNativeInfluenceAuthority<'_, '_, '_>,
    binding: &NativeSecurityAuthorityBindingV1,
    slot: &NativeInfluenceSlot,
) -> Result<VerifiedAuthorityCoverage, AdmissionOperationStoreError> {
    let tx = custody.transaction();
    let row = protected::raw_checked(tx, slot.record_key())?
        .ok_or_else(|| invalid("current influence authority head is absent"))?;
    let source = protected::source_reference(tx, slot.record_key())?;
    verify_header(tx, slot, &row, &source)?;
    let head: AuthorityHead = protected::decode(&row.payload)?;
    if head.native_authority != *binding
        || head.revision.get() != row.version
        || head.initialization_fingerprint != custody.initialization().fingerprint
        || head.catalog_global_sequence.get() == 0
        || head.catalog_global_sequence.get() != source.global_commit_sequence()
        || source.global_commit_sequence() > custody.current_global_sequence()
    {
        return Err(invalid("current influence authority coverage changed"));
    }
    // This catalog is installed only with the entire authenticated source
    // union. A missing, changed or stale catalog cannot assert clean genesis.
    let (catalog_digest, global_sequence): (String, i64) = tx
        .query_row(
            "SELECT catalog_digest,global_commit_sequence FROM admission_operation_native_source_catalog
             WHERE security_authority_id=?1 AND initialization_digest=?2",
            params![binding.security_authority_id().as_str(), binding.initialization_digest().as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or_else(|| invalid("current native source catalog is absent"))?;
    if catalog_digest != hex::encode(head.current_source_catalog.as_bytes())
        || u64::try_from(global_sequence).map_err(invalid)? != head.catalog_global_sequence.get()
    {
        return Err(invalid("current native source catalog is stale"));
    }
    // source_reference already matched the actual immutable recovery EVENT
    // digest to its unique global reference. Its digest() getter is the record
    // digest, a different preimage, and must not be compared with that event.
    protected::verify_source_reference(tx, &source)?;
    Ok(VerifiedAuthorityCoverage {
        relevant_observations: head.observations.get(),
    })
}

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

fn verify_header(
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
