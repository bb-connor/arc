//! Native identifier refusal that survives checkpoint compaction.
//!
//! Current rows hold imported identities and those created since the last
//! checkpoint. The immutable family journals hold every native identity. Each
//! lookup is a point query on a unique journal index, never a history scan.
use super::*;

const CURRENT_TRANSITION: &str =
    "SELECT EXISTS(SELECT 1 FROM security_participant_state_transitions
    WHERE security_authority_id = ?1 AND tenant_id = ?2 AND transition_id = ?3)";
const JOIN_TRANSITION: &str = "SELECT EXISTS(SELECT 1 FROM security_participant_state_mutations
    WHERE security_authority_id = ?1 AND tenant_id = ?2 AND transition_id = ?3)";
const OUTPUT_TRANSITION: &str = "SELECT EXISTS(SELECT 1 FROM security_participant_output_events
    WHERE security_authority_id = ?1 AND tenant_id = ?2 AND transition_id = ?3)";
const PREFLIGHT_TRANSITION: &str =
    "SELECT EXISTS(SELECT 1 FROM security_participant_nonce_preflight_events
    WHERE security_authority_id = ?1 AND tenant_id = ?2 AND transition_id = ?3)";
// A fence identifier is unique across tenants of one authority.
const CURRENT_FENCE: &str = "SELECT EXISTS(SELECT 1 FROM security_participant_state_egress_fences
        WHERE security_authority_id = ?1 AND tenant_id = ?2 AND request_id = ?3)
    OR EXISTS(SELECT 1 FROM security_participant_state_egress_fences
        WHERE security_authority_id = ?1 AND fence_id = ?4)";
const RETAINED_FENCE: &str = "SELECT EXISTS(SELECT 1 FROM security_participant_egress_events
        WHERE security_authority_id = ?1 AND tenant_id = ?2 AND request_id = ?3)
    OR EXISTS(SELECT 1 FROM security_participant_egress_events
        WHERE security_authority_id = ?1 AND fence_id = ?4)";

fn exists(
    connection: &Connection,
    query: &str,
    parameters: impl rusqlite::Params,
) -> Result<bool, AdmissionOperationStoreError> {
    connection
        .query_row(query, parameters, |row| row.get(0))
        .map_err(sqlite_error)
}

/// Whether a flow transition identifier is current or retained by any native
/// join family, so no other operation or family can claim it.
pub(in crate::admission_operation_store) fn transition_occupied(
    connection: &Connection,
    authority: &str,
    tenant: &str,
    transition: &str,
) -> Result<bool, AdmissionOperationStoreError> {
    let mut holders = vec![CURRENT_TRANSITION, JOIN_TRANSITION];
    if output::exists(connection)? {
        holders.push(OUTPUT_TRANSITION);
    }
    if nonce_preflight::exists(connection)? {
        holders.push(PREFLIGHT_TRANSITION);
    }
    for query in holders {
        if exists(connection, query, params![authority, tenant, transition])? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether an egress request or fence identifier is current or retained by
/// the native egress journal.
pub(in crate::admission_operation_store) fn fence_occupied(
    connection: &Connection,
    authority: &str,
    tenant: &str,
    request: &str,
    fence: &str,
) -> Result<bool, AdmissionOperationStoreError> {
    for query in [CURRENT_FENCE, RETAINED_FENCE] {
        if exists(
            connection,
            query,
            params![authority, tenant, request, fence],
        )? {
            return Ok(true);
        }
    }
    Ok(false)
}
