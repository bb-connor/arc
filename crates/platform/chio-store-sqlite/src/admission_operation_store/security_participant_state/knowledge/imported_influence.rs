//! Conservative influence contributed by verified sealed pre-recovery history.
//!
//! Imported rows are genuine predecessor source custody, not active flow state
//! and not experimental admission-format compatibility. Their origin
//! classifications are unknown here: no imported row ever grants a trusted
//! external classification. A row contributes only under the same inherited
//! flow rules as native joins (matching tenant plus lineage or
//! principal-and-epoch); a foreign tenant's retained history never
//! contaminates another flow. Lifecycle metadata alone contributes nothing.
//!
//! The warm reader reads only the requested flow's scopes through the
//! authenticated scope index, so its work never depends on the retained history
//! of any other tenant or flow.
use super::influence_slots::ImportedInfluenceScope;
use super::*;
use crate::security_state::retained_security_columns;
use chio_security_types::knowledge::ArtifactInfluenceV1;
use chio_security_types::ports::{FlowStateKey, IsolationEpochId, LineageId, TenantId};
use chio_security_types::recovery::CanonicalPayloadDigest;
use rusqlite::types::Value;
use std::collections::BTreeMap;

#[cfg(test)]
mod full_scan_oracle;
#[cfg(test)]
pub(in crate::admission_operation_store) use full_scan_oracle::full_scan_commitment;
mod scope_index;
pub(crate) use scope_index::publish_imported_influence_roots_at_startup;
pub(in crate::admission_operation_store) use scope_index::{
    historical_root_pending, install_imported_scope_index, verify_imported_scope_index,
    verify_imported_scope_index_coverage, VerifiedImportedInfluenceRoot,
};

/// Flow-bearing source tables whose retained rows can carry confidentiality.
/// The declassification lifecycle is metadata and deliberately absent.
const RELEVANT_TABLES: [&str; 9] = [
    "security_flow_contexts",
    "security_lineage_flow_state",
    "security_principal_flow_state",
    "security_session_flow_state",
    "security_transitions",
    "security_egress_fences",
    "security_declassification_uses",
    "security_declassification_evidence_identity",
    "security_declassification_receipt_outbox",
];

/// Bounded field lookup against the exact retained column layout.
fn field<'a>(
    table: &str,
    values: &'a [Value],
    name: &str,
) -> Result<&'a str, AdmissionOperationStoreError> {
    let columns = retained_security_columns(table).map_err(invalid)?;
    let index = columns
        .iter()
        .position(|column| *column == name)
        .ok_or_else(|| invalid("retained source column is absent"))?;
    match values.get(index) {
        Some(Value::Text(text)) => Ok(text.as_str()),
        _ => Err(invalid("retained source field is not text")),
    }
}

/// Whether one decoded retained row matches this flow under the inherited
/// scope rules: same tenant AND (same lineage OR same principal-and-epoch).
///
/// This is exactly the union the native reader applies to its own joined
/// rows (knowledge.rs observed_influence_with_head). A stricter match here
/// (all key fields equal, session included) would drop source custody that
/// the native rules inherit: for example, prior source context recorded
/// under the same lineage but a different session, or the same principal in a
/// new epoch, would disappear from the lineage-inherited contribution and
/// the imported history would silently under-report influence, violating the
/// additive-only influence contract. Session and full-field equality can
/// only narrow a contribution the native reader would make, never widen it,
/// so the conservative imported reader must reuse the same union.
///
/// State tables carry lineage or principal/epoch identity and match it;
/// contexts and egress fences carry every flow key field and apply the same
/// lineage-or-(principal,epoch) union on the fields they retain; transitions
/// and declassification rows expose no finer flow identity than their tenant,
/// so they conservatively match this tenant only. A foreign tenant never
/// matches in any table.
fn matches_flow(
    table: &str,
    values: &[Value],
    key: &FlowStateKey,
) -> Result<bool, AdmissionOperationStoreError> {
    if field(table, values, "tenant_id")? != key.tenant_id.as_str() {
        return Ok(false);
    }
    Ok(match table {
        "security_lineage_flow_state" => {
            field(table, values, "lineage_id")? == key.lineage_id.as_str()
        }
        "security_principal_flow_state" | "security_session_flow_state" => {
            field(table, values, "principal_id")? == key.principal_id.as_str()
                && field(table, values, "isolation_epoch_id")? == key.isolation_epoch_id.as_str()
        }
        // Contexts and egress fences retain lineage and principal/epoch
        // identity of the flows they record; session identity is not part of
        // the inherited union and must not narrow the contribution.
        "security_flow_contexts" | "security_egress_fences" => {
            field(table, values, "lineage_id")? == key.lineage_id.as_str()
                || (field(table, values, "principal_id")? == key.principal_id.as_str()
                    && field(table, values, "isolation_epoch_id")?
                        == key.isolation_epoch_id.as_str())
        }
        // Transitions and declassification rows expose no finer flow
        // identity than their tenant; a same-tenant match conservatively
        // contributes unknown without claiming any finer provenance.
        _ => true,
    })
}

fn lineage_scope(
    table: &str,
    values: &[Value],
    tenant: TenantId,
) -> Result<ImportedInfluenceScope, AdmissionOperationStoreError> {
    Ok(ImportedInfluenceScope::Lineage {
        tenant,
        lineage: LineageId::new(field(table, values, "lineage_id")?).map_err(invalid)?,
    })
}

fn principal_scope(
    table: &str,
    values: &[Value],
    tenant: TenantId,
) -> Result<ImportedInfluenceScope, AdmissionOperationStoreError> {
    Ok(ImportedInfluenceScope::Principal {
        tenant,
        principal: chio_security_types::PrincipalId::new(field(table, values, "principal_id")?)
            .map_err(invalid)?,
        epoch: IsolationEpochId::new(field(table, values, "isolation_epoch_id")?)
            .map_err(invalid)?,
    })
}

/// The scopes one decoded retained row belongs to. This is the inverse of
/// `matches_flow`: a row is a member of exactly the scopes of every flow it
/// matches, so reading a flow's three scopes selects exactly the rows
/// `matches_flow` accepts for it.
fn assigned_scopes(
    table: &str,
    values: &[Value],
) -> Result<Vec<ImportedInfluenceScope>, AdmissionOperationStoreError> {
    let tenant = TenantId::new(field(table, values, "tenant_id")?).map_err(invalid)?;
    Ok(match table {
        "security_lineage_flow_state" => vec![lineage_scope(table, values, tenant)?],
        "security_principal_flow_state" | "security_session_flow_state" => {
            vec![principal_scope(table, values, tenant)?]
        }
        "security_flow_contexts" | "security_egress_fences" => vec![
            lineage_scope(table, values, tenant.clone())?,
            principal_scope(table, values, tenant)?,
        ],
        _ => vec![ImportedInfluenceScope::Tenant { tenant }],
    })
}

/// The conservative imported contribution to one flow's influence.
///
/// The caller holds the owning transaction. Metadata, the protected index root
/// and each requested scope's leaf or absence are authenticated first, with
/// their bounded work charged before any index row is read; then every member
/// of a present scope is charged before its list is loaded and its actual
/// current sealed source row is fetched and rehashed. Nothing here scans the
/// retained source or depends on any other flow's history.
pub(super) fn observed(
    tx: &Connection,
    binding: &NativeSecurityAuthorityBindingV1,
    key: &FlowStateKey,
    budget: &mut chio_semantic_contracts::VerificationBudget,
) -> Result<Option<ArtifactInfluenceV1>, AdmissionOperationStoreError> {
    use chio_core::recovery::{knowledge_digest, RecoveryDigestDomain};
    let authority = binding.security_authority_id().as_str();
    // Current owner, initialization, destination, expectation and imported
    // existence checks all live in this authenticated metadata read.
    budget.charge(scope_index::ROOT_WORK).map_err(invalid)?;
    if !security_participant_migration::verify_catalog(tx)? {
        return Err(invalid("imported source catalog is absent"));
    }
    let initialization = records::load_current_metadata(tx, binding)?;
    let root = scope_index::authenticate_root(tx, binding, &initialization)?;
    // One entry per source row even when it belongs to several scopes, ordered
    // by relevant table and row index.
    let mut selected: BTreeMap<(u16, u32), String> = BTreeMap::new();
    for scope in ImportedInfluenceScope::inherited(key) {
        let scope_key = scope.scope_key(binding)?;
        for member in
            scope_index::read_scope_members(tx, authority, &root, key, &scope_key, budget)?
        {
            selected.insert((member.ordinal, member.row_index), member.row_digest);
        }
    }
    if selected.is_empty() {
        // No matched flow: no imported history is this flow's influence. This
        // is per-flow absence, not an authority-wide fallback contribution
        // and not a normalized digest of an empty contribution set.
        return Ok(None);
    }
    let contributions: Vec<(&'static str, String)> = selected
        .into_iter()
        .map(|((ordinal, _), digest)| (RELEVANT_TABLES[usize::from(ordinal)], digest))
        .collect();
    Ok(Some(ArtifactInfluenceV1 {
        // Exact commitment over the sealed source, the queried flow and every
        // selected contribution. No empty-hash normalization, no global marker.
        commitment: CanonicalPayloadDigest::from_bytes(
            knowledge_digest(
                RecoveryDigestDomain::KnowledgeObservedInfluence,
                &(
                    &initialization.fingerprint,
                    authority,
                    binding.store_uuid().as_str(),
                    key,
                    &contributions,
                ),
            )
            .map_err(invalid)?,
        ),
        // Imported origin classifications are unknown, never trusted external.
        externally_influenced: false,
        unknown: true,
    }))
}
