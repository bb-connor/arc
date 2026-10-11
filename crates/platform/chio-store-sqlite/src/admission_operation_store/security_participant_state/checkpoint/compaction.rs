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
//! - a whole session (its label, membership and every context under any
//!   lineage) whose label adds nothing to its principal label, which no egress
//!   fence names, and which no unfinished operation's retained context names.
//!   Principal labels are only joined upward and never leave, so every later
//!   reader, including a first join that reuses the session identifier,
//!   computes the same labels. Only the context generation token is new.
//!
//! Imported rows (including imported sessions), pending unexpired fences,
//! principal and lineage labels, isolation epochs, sequences and any session
//! carrying taint its principal lacks stay current.
use super::*;
use crate::security_state::{
    decode_retained_security_row, encode_retained_security_values, retained_security_columns,
};
use rusqlite::types::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Unfinished operations whose retained context can pin a session. Past this
/// many, or with any context that is not exact text, no session leaves.
const MAX_PINNING_OPERATIONS: u64 = 1_024;

#[cfg(test)]
thread_local! {
    static TEST_PINNING_OPERATIONS: std::cell::Cell<u64> =
        const { std::cell::Cell::new(MAX_PINNING_OPERATIONS) };
}

/// Lower, never raise, the pinning-operation bound for one test thread.
#[cfg(test)]
pub(in crate::admission_operation_store) fn with_test_pinning_operations<T>(
    operations: u64,
    run: impl FnOnce() -> T,
) -> T {
    assert!((1..=MAX_PINNING_OPERATIONS).contains(&operations));
    struct Reset(u64);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_PINNING_OPERATIONS.set(self.0);
        }
    }
    let _reset = Reset(TEST_PINNING_OPERATIONS.replace(operations));
    run()
}

fn pinning_bound() -> u64 {
    #[cfg(test)]
    return TEST_PINNING_OPERATIONS.get();
    #[cfg(not(test))]
    MAX_PINNING_OPERATIONS
}

/// Retained native contexts of unfinished operations, through the terminal
/// index. Any operation without a retained request cannot hold native custody.
const PINNING: &str = "SELECT
        json_type(CAST(request.request_json AS TEXT), '$.security_binding.native_authority'),
        json_type(CAST(request.request_json AS TEXT), '$.security_binding.context'),
        json_extract(CAST(request.request_json AS TEXT), '$.security_binding.context.tenant_id'),
        json_extract(CAST(request.request_json AS TEXT), '$.security_binding.context.principal_id'),
        json_extract(CAST(request.request_json AS TEXT), '$.security_binding.context.session_id'),
        json_extract(CAST(request.request_json AS TEXT), '$.security_binding.context.isolation_epoch_id')
    FROM (SELECT operation_id FROM admission_operations WHERE terminal = 0 LIMIT ?1) AS operation
    LEFT JOIN admission_operation_tool_requests AS request
        ON request.operation_id = operation.operation_id";

type SessionKey = (String, String, String, String);

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
            push(&mut rows, table, String::from_utf8(image).map_err(invalid)?)?;
        }
    }
    sessions(tx, authority, &mut rows)?;
    Ok(rows)
}

fn push(
    rows: &mut Vec<(&'static str, String)>,
    table: &'static str,
    image: String,
) -> Result<(), AdmissionOperationStoreError> {
    rows.push((table, image));
    if rows.len() > 65_536 {
        return Err(invalid("native compaction plan exceeds bounds"));
    }
    Ok(())
}

/// Sessions named by unfinished operations, or `None` when that evidence is
/// incomplete or exceeds its bound.
fn pinned_sessions(
    tx: &Transaction<'_>,
) -> Result<Option<BTreeSet<SessionKey>>, AdmissionOperationStoreError> {
    let bound = pinning_bound();
    let mut statement = tx.prepare(PINNING).map_err(sqlite_error)?;
    let mut selected = statement
        .query([i64::try_from(bound + 1).map_err(invalid)?])
        .map_err(sqlite_error)?;
    let mut scanned = 0_u64;
    let mut pinned = BTreeSet::new();
    while let Some(row) = selected.next().map_err(sqlite_error)? {
        scanned += 1;
        if scanned > bound {
            return Ok(None);
        }
        let native: Option<String> = row.get(0).map_err(sqlite_error)?;
        let context: Option<String> = row.get(1).map_err(sqlite_error)?;
        match (native.as_deref(), context.as_deref()) {
            (None | Some("null"), None | Some("null")) => continue,
            (_, Some("object")) => {}
            _ => return Ok(None),
        }
        let mut fields = Vec::with_capacity(4);
        for index in 2..6 {
            match row.get_ref(index).map_err(sqlite_error)? {
                rusqlite::types::ValueRef::Text(text) => {
                    fields.push(String::from_utf8(text.to_vec()).map_err(invalid)?);
                }
                _ => return Ok(None),
            }
        }
        let [tenant, principal, session, epoch]: [String; 4] = fields
            .try_into()
            .map_err(|_| invalid("native pinning context is malformed"))?;
        pinned.insert((tenant, principal, session, epoch));
    }
    Ok(Some(pinned))
}

/// Sessions present in the imported source. They stay current, as every
/// other imported row does.
fn imported_sessions(
    tx: &Transaction<'_>,
    authority: &str,
) -> Result<BTreeSet<SessionKey>, AdmissionOperationStoreError> {
    const TABLE: &str = "security_session_flow_state";
    let fields = retained_security_columns(TABLE).map_err(invalid)?;
    let position = |name: &str| {
        fields
            .iter()
            .position(|field| *field == name)
            .ok_or_else(|| invalid("native session column is absent"))
    };
    let columns = [
        position("tenant_id")?,
        position("principal_id")?,
        position("session_id")?,
        position("isolation_epoch_id")?,
    ];
    let mut statement = tx
        .prepare(
            "SELECT canonical_row FROM security_participant_migration_rows
             WHERE security_authority_id = ?1 AND table_name = ?2 LIMIT 65537",
        )
        .map_err(sqlite_error)?;
    let mut selected = statement
        .query(params![authority, TABLE])
        .map_err(sqlite_error)?;
    let mut imported = BTreeSet::new();
    while let Some(row) = selected.next().map_err(sqlite_error)? {
        let bytes = row
            .get_ref(0)
            .map_err(sqlite_error)?
            .as_blob()
            .map_err(invalid)?;
        let values = decode_retained_security_row(TABLE, bytes).map_err(invalid)?;
        let text = |index: usize| match values.get(index) {
            Some(Value::Text(text)) => Ok(text.clone()),
            _ => Err(invalid("imported native session key is malformed")),
        };
        imported.insert((
            text(columns[0])?,
            text(columns[1])?,
            text(columns[2])?,
            text(columns[3])?,
        ));
    }
    Ok(imported)
}

/// Every current row of one session-scoped table, by session.
fn visit_session_rows(
    tx: &Transaction<'_>,
    authority: &str,
    table: &'static str,
    native: &str,
    mut visit: impl FnMut(SessionKey, String) -> Result<(), AdmissionOperationStoreError>,
) -> Result<(), AdmissionOperationStoreError> {
    let fields = retained_security_columns(table).map_err(invalid)?;
    let columns = fields
        .iter()
        .map(|field| format!("state.\"{field}\""))
        .collect::<Vec<_>>()
        .join(",");
    let mut statement = tx
        .prepare(&format!(
            "SELECT state.tenant_id, state.principal_id, state.session_id, state.isolation_epoch_id,
             {columns} FROM {native} AS state WHERE state.security_authority_id = ?1
             ORDER BY {columns} LIMIT 65537"
        ))
        .map_err(sqlite_error)?;
    let mut selected = statement.query([authority]).map_err(sqlite_error)?;
    while let Some(row) = selected.next().map_err(sqlite_error)? {
        let key = (
            row.get(0).map_err(sqlite_error)?,
            row.get(1).map_err(sqlite_error)?,
            row.get(2).map_err(sqlite_error)?,
            row.get(3).map_err(sqlite_error)?,
        );
        let values = (4..4 + fields.len())
            .map(|index| row.get_ref(index))
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(sqlite_error)?;
        let image = encode_retained_security_values(table, &values).map_err(invalid)?;
        visit(key, String::from_utf8(image).map_err(invalid)?)?;
    }
    Ok(())
}

/// Plan whole dominated native sessions that no fence or unfinished operation
/// names.
fn sessions(
    tx: &Transaction<'_>,
    authority: &str,
    rows: &mut Vec<(&'static str, String)>,
) -> Result<(), AdmissionOperationStoreError> {
    let Some(pinned) = pinned_sessions(tx)? else {
        return Ok(());
    };
    let imported = imported_sessions(tx, authority)?;
    let mut fenced = BTreeSet::new();
    let mut statement = tx
        .prepare(
            "SELECT DISTINCT tenant_id, principal_id, session_id, isolation_epoch_id
             FROM security_participant_state_egress_fences WHERE security_authority_id = ?1",
        )
        .map_err(sqlite_error)?;
    let mut selected = statement.query([authority]).map_err(sqlite_error)?;
    while let Some(row) = selected.next().map_err(sqlite_error)? {
        fenced.insert((
            row.get(0).map_err(sqlite_error)?,
            row.get(1).map_err(sqlite_error)?,
            row.get(2).map_err(sqlite_error)?,
            row.get(3).map_err(sqlite_error)?,
        ));
    }
    let mut contexts = BTreeMap::<SessionKey, Vec<String>>::new();
    visit_session_rows(
        tx,
        authority,
        "security_flow_contexts",
        "security_participant_state_flow_contexts",
        |key, image| {
            contexts.entry(key).or_default().push(image);
            Ok(())
        },
    )?;
    let mut members = BTreeMap::new();
    visit_session_rows(
        tx,
        authority,
        "security_session_memberships",
        "security_participant_state_session_memberships",
        |key, image| match members.insert(key, image) {
            None => Ok(()),
            Some(_) => Err(invalid("native session membership is duplicated")),
        },
    )?;
    let mut labels = Vec::new();
    visit_session_rows(
        tx,
        authority,
        "security_session_flow_state",
        "security_participant_state_session_flow_state",
        |key, image| {
            labels.push((key, image));
            Ok(())
        },
    )?;
    for (key, image) in labels {
        if pinned.contains(&key) || fenced.contains(&key) || imported.contains(&key) {
            continue;
        }
        let (tenant, principal, session, epoch) = &key;
        if !crate::security_state::native_session_dominated(
            tx,
            authority,
            [tenant, principal, session, epoch],
        )
        .map_err(invalid)?
        {
            continue;
        }
        let membership = members
            .remove(&key)
            .ok_or_else(|| invalid("native session membership is absent"))?;
        push(rows, "security_session_flow_state", image)?;
        push(rows, "security_session_memberships", membership)?;
        for context in contexts.remove(&key).unwrap_or_default() {
            push(rows, "security_flow_contexts", context)?;
        }
    }
    Ok(())
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
