//! Finished current rows leave the sealed snapshot. Their identities remain in
//! the immutable family journals, which every native writer also consults.
//!
//! A row is dead only when no later native command can read it:
//! - a `flow_join` transition whose identifier one of the three join-family
//!   journals retains. Writers refuse the identifier from those journals.
//! - a natively acquired egress fence that is committed, or still pending
//!   after its expiry. Commitment is terminal and retries return journal
//!   history; the native clock floor never falls back below the checkpoint
//!   time, so an expired fence cannot commit.
//!
//! Imported rows, pending unexpired fences and all flow labels stay current.
use super::*;
use crate::security_state::{encode_retained_security_values, retained_security_columns};

const TRANSITIONS: &str = "SELECT {columns} FROM security_participant_state_transitions AS state
    WHERE state.security_authority_id = ?1 AND state.transition_kind = 'flow_join'
      AND (EXISTS(SELECT 1 FROM security_participant_state_mutations AS journal
              WHERE journal.security_authority_id = state.security_authority_id
                AND journal.tenant_id = state.tenant_id AND journal.transition_id = state.transition_id)
        OR EXISTS(SELECT 1 FROM security_participant_output_events AS journal
              WHERE journal.security_authority_id = state.security_authority_id
                AND journal.tenant_id = state.tenant_id AND journal.transition_id = state.transition_id)
        OR EXISTS(SELECT 1 FROM security_participant_nonce_preflight_events AS journal
              WHERE journal.security_authority_id = state.security_authority_id
                AND journal.tenant_id = state.tenant_id AND journal.transition_id = state.transition_id))
    ORDER BY {columns} LIMIT 65537";

const FENCES: &str = "SELECT {columns} FROM security_participant_state_egress_fences AS state
    WHERE state.security_authority_id = ?1
      AND EXISTS(SELECT 1 FROM security_participant_egress_events AS acquired
          WHERE acquired.security_authority_id = state.security_authority_id
            AND acquired.fence_id = state.fence_id AND acquired.phase = 'acquired'
            AND acquired.tenant_id = state.tenant_id AND acquired.request_id = state.request_id)
      AND ((state.dispatch_commitment_id IS NOT NULL AND state.committed_at IS NOT NULL
            AND EXISTS(SELECT 1 FROM security_participant_egress_events AS committed
                WHERE committed.security_authority_id = state.security_authority_id
                  AND committed.fence_id = state.fence_id AND committed.phase = 'committed'
                  AND committed.tenant_id = state.tenant_id AND committed.request_id = state.request_id))
        OR (state.dispatch_commitment_id IS NULL AND state.committed_at IS NULL
            AND state.expires_at <= ?2
            AND NOT EXISTS(SELECT 1 FROM security_participant_egress_events AS committed
                WHERE committed.security_authority_id = state.security_authority_id
                  AND committed.fence_id = state.fence_id AND committed.phase = 'committed')))
    ORDER BY {columns} LIMIT 65537";

/// Affine, crate-private authority minted only inside an authenticated
/// checkpoint transaction. It names exact dead row images, never a predicate,
/// and grants no join, egress, dispatch or release authority.
pub(crate) struct NativeCompactionAuthority {
    authority: String,
    compacted_at: u64,
    rows: Vec<(&'static str, String)>,
}

impl NativeCompactionAuthority {
    pub(crate) fn authority(&self) -> &str {
        &self.authority
    }

    pub(crate) fn compacted_at(&self) -> u64 {
        self.compacted_at
    }

    pub(crate) fn rows(&self) -> &[(&'static str, String)] {
        &self.rows
    }
}

/// Exact images of the authenticated dead rows of one initialized authority.
pub(super) fn plan(
    tx: &Transaction<'_>,
    authority: &str,
    compacted_at: u64,
) -> Result<Vec<(&'static str, String)>, AdmissionOperationStoreError> {
    let compacted_at = i64::try_from(compacted_at).map_err(invalid)?;
    let mut rows = Vec::new();
    for (table, query) in [
        ("security_transitions", TRANSITIONS),
        ("security_egress_fences", FENCES),
    ] {
        let fields = retained_security_columns(table).map_err(invalid)?;
        let columns = fields
            .iter()
            .map(|field| format!("state.\"{field}\""))
            .collect::<Vec<_>>()
            .join(",");
        let mut statement = tx
            .prepare(&query.replace("{columns}", &columns))
            .map_err(sqlite_error)?;
        let selected = if table == "security_transitions" {
            statement.query(params![authority])
        } else {
            statement.query(params![authority, compacted_at])
        };
        let mut selected = selected.map_err(sqlite_error)?;
        while let Some(row) = selected.next().map_err(sqlite_error)? {
            let values = (0..fields.len())
                .map(|index| row.get_ref(index))
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(sqlite_error)?;
            let image = encode_retained_security_values(table, &values).map_err(invalid)?;
            rows.push((table, String::from_utf8(image).map_err(invalid)?));
            if rows.len() > 65_536 {
                return Err(invalid("native compaction plan exceeds bounds"));
            }
        }
    }
    Ok(rows)
}

/// Delete exactly the planned rows inside the caller's checkpoint transaction,
/// before its snapshot is copied.
pub(super) fn compact<'connection>(
    tx: Transaction<'connection>,
    authority: &str,
    compacted_at: u64,
    rows: Vec<(&'static str, String)>,
) -> Result<Transaction<'connection>, AdmissionOperationStoreError> {
    if rows.is_empty() {
        return Ok(tx);
    }
    let planned = u64::try_from(rows.len()).map_err(invalid)?;
    let authorization = NativeCompactionAuthority {
        authority: authority.to_owned(),
        compacted_at,
        rows,
    };
    let (tx, deleted) =
        crate::security_state::compact_native_rows(tx, authorization).map_err(invalid)?;
    if deleted != planned {
        return Err(invalid("native compaction differs from its plan"));
    }
    Ok(tx)
}
