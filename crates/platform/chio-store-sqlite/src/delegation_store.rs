//! Qualified D1 allocator under the serving authority.
//!
//! Every mutation runs in one immediate transaction behind the serving fence,
//! binds an immutable command id to its exact request digest, applies the
//! shared `chio_workflow::delegation::transition` rules and appends one event
//! covered by the global authority commit chain. Sealed allocations are never
//! released, and an expired permit stays readable only as history.

use std::sync::Arc;

use chio_core::crypto::{Keypair, PublicKey};
use chio_core::{sha256_hex, StoreMutationFence};
use chio_workflow::delegation::transition::{
    self, RootOutcome, SelectionOutcome, SlotState, SubdivisionCounts, SubdivisionOutcome,
};
use chio_workflow::delegation::{
    Admission, DelegationError, DispatchBinding, DispatchPermit, Selection, Signed, Subdivision,
    WorkSlot, MAX_ENVELOPE_BYTES,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::Serialize;

use crate::admission_operation_store::{verify_active_owner, verify_trusted_time};
use crate::serving_owner::{SqliteServingOwner, SqliteServingOwnerError};
use crate::store_connection::{StoreConnection, StoreGuard};

mod schema;

pub(crate) use schema::{
    initialize_work_delegation_schema, projection_reference, verify_projection_coverage,
    verify_work_delegation_invariants, PROJECTION,
};

#[derive(Debug, thiserror::Error)]
pub enum SqliteDelegationStoreError {
    #[error(transparent)]
    Rule(#[from] DelegationError),
    #[error("delegation command conflicts with its retained request")]
    CommandConflict,
    #[error("delegation store is unavailable: {0}")]
    Unavailable(String),
    #[error("delegation store invariant failed: {0}")]
    Invalid(String),
}

type Result<T> = std::result::Result<T, SqliteDelegationStoreError>;

#[derive(Clone, Copy)]
enum Action {
    CreateRoot,
    Subdivide,
    Select,
    Claim,
    Seal,
}

impl Action {
    const fn as_str(self) -> &'static str {
        match self {
            Self::CreateRoot => "create_root",
            Self::Subdivide => "subdivide",
            Self::Select => "select",
            Self::Claim => "claim",
            Self::Seal => "seal",
        }
    }
}

/// Serving-bound D1 allocator. Construct it with
/// [`crate::SqliteAuthorityStore::delegation_store`].
pub struct SqliteDelegationStore {
    connection: Arc<StoreConnection>,
    serving_owner: Arc<SqliteServingOwner>,
}

impl SqliteDelegationStore {
    pub(crate) fn open_alongside(
        connection: Arc<StoreConnection>,
        serving_owner: Arc<SqliteServingOwner>,
    ) -> Self {
        Self {
            connection,
            serving_owner,
        }
    }

    pub fn mutation_fence(&self) -> StoreMutationFence {
        self.serving_owner.fence.clone()
    }

    /// Trusted owner configuration only. This does not verify an end-user grant.
    pub fn create_root(
        &self,
        command_id: &str,
        slot: WorkSlot,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<()> {
        let digest = request_digest(Action::CreateRoot, &slot)?;
        self.mutate(fence, trusted_now_unix_ms, |tx, _| {
            let existing = read(tx, &slot.id)?;
            match transition::create_root(slot.clone(), existing.as_ref())? {
                RootOutcome::Existing => {
                    bind_command(tx, command_id, Action::CreateRoot, &digest, &slot.id)?;
                    Ok(None)
                }
                RootOutcome::Insert(row) => {
                    insert(tx, &row)?;
                    bind_command(tx, command_id, Action::CreateRoot, &digest, &row.slot.id)?;
                    Ok(Some((command_id.to_owned(), vec![*row])))
                }
            }
        })
        .map(|_| ())
    }

    pub fn slot(&self, id: &str) -> Result<WorkSlot> {
        self.read_only(|tx| Ok(required(tx, id)?.slot))
    }

    /// Bind a mutation or offer to this allocator and the exact root and slot.
    pub fn allocation_digest(&self, id: &str) -> Result<String> {
        self.read_only(|tx| {
            let row = required(tx, id)?;
            allocation_digest(tx, &row)
        })
    }

    pub fn subdivide(
        &self,
        command_id: &str,
        request: &Signed<Subdivision>,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<WorkSlot> {
        let digest = request_digest(Action::Subdivide, request)?;
        let mut result = None;
        self.mutate(fence, trusted_now_unix_ms, |tx, now| {
            replayed_command(tx, command_id, Action::Subdivide, &digest)?;
            let parent = required(tx, &request.body.parent_id)?;
            let parent_hash = allocation_digest(tx, &parent)?;
            let existing = read(tx, &request.body.child.id)?;
            let counts = SubdivisionCounts {
                children: count(tx, "parent_id", &parent.slot.id)?,
                root_slots: count(tx, "root_id", &parent.root)?,
            };
            match transition::subdivide(
                request,
                &parent,
                &parent_hash,
                existing.as_ref(),
                counts,
                now,
            )? {
                SubdivisionOutcome::Existing(slot) => {
                    bind_command(tx, command_id, Action::Subdivide, &digest, &slot.id)?;
                    result = Some(*slot);
                    Ok(None)
                }
                SubdivisionOutcome::Insert {
                    child,
                    parent_allocated,
                } => {
                    insert(tx, &child)?;
                    bind_command(tx, command_id, Action::Subdivide, &digest, &child.slot.id)?;
                    tx.execute(
                        "UPDATE work_delegation_slots SET allocated = ?1 WHERE slot_id = ?2",
                        params![sql_u64(parent_allocated)?, parent.slot.id],
                    )
                    .map_err(sqlite_error)?;
                    let mut updated = parent;
                    updated.allocated = parent_allocated;
                    result = Some(child.slot.clone());
                    Ok(Some((command_id.to_owned(), vec![*child, updated])))
                }
            }
        })?;
        result.ok_or_else(|| invalid("subdivision produced no slot"))
    }

    /// Enrollment in `qualified` is trusted local configuration, never a field
    /// from an offer.
    pub fn select(
        &self,
        command_id: &str,
        request: &Signed<Selection>,
        qualified: &[PublicKey],
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<()> {
        let digest = request_digest(Action::Select, request)?;
        self.mutate(fence, trusted_now_unix_ms, |tx, now| {
            replayed_command(tx, command_id, Action::Select, &digest)?;
            let row = required(tx, &request.body.offer.body.slot_id)?;
            let allocation_hash = allocation_digest(tx, &row)?;
            let children = count(tx, "parent_id", &row.slot.id)?;
            match transition::select(request, &row, &allocation_hash, children, now, qualified)? {
                SelectionOutcome::Unchanged => {
                    bind_command(tx, command_id, Action::Select, &digest, &row.slot.id)?;
                    Ok(None)
                }
                SelectionOutcome::Replace { revision } => {
                    bind_command(tx, command_id, Action::Select, &digest, &row.slot.id)?;
                    tx.execute(
                        "UPDATE work_delegation_slots SET selection = ?1, revision = ?2 WHERE slot_id = ?3",
                        params![encode(request)?, sql_u64(revision)?, row.slot.id],
                    )
                    .map_err(sqlite_error)?;
                    let mut updated = row;
                    updated.selection = Some(request.clone());
                    updated.revision = revision;
                    Ok(Some((command_id.to_owned(), vec![updated])))
                }
            }
        })
        .map(|_| ())
    }

    /// Irreversible allocation claim. Native operation replay is a separate,
    /// required boundary; idempotence here is not permission to repeat an effect.
    pub fn claim_dispatch(
        &self,
        command_id: &str,
        binding: &DispatchBinding,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<Admission> {
        let digest = request_digest(Action::Claim, binding)?;
        let mut result = None;
        self.mutate(fence, trusted_now_unix_ms, |tx, now| {
            replayed_command(tx, command_id, Action::Claim, &digest)?;
            let row = required(tx, &binding.slot_id)?;
            let allocation_hash = allocation_digest(tx, &row)?;
            let admission = transition::claim(&row, &allocation_hash, binding, now)?;
            result = Some(admission);
            bind_command(tx, command_id, Action::Claim, &digest, &row.slot.id)?;
            if row.dispatched {
                return Ok(None);
            }
            mark_dispatched(tx, &row.slot.id)?;
            let mut updated = row;
            updated.dispatched = true;
            Ok(Some((command_id.to_owned(), vec![updated])))
        })?;
        result.ok_or_else(|| invalid("claim produced no admission"))
    }

    /// Commit before returning portable evidence. The signing key belongs to
    /// allocator configuration, not a holder request. Sealing forbids
    /// replacement even before receiver execution. Retries return the original
    /// signed bytes.
    pub fn seal_dispatch(
        &self,
        command_id: &str,
        binding: &DispatchBinding,
        issuer: &Keypair,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<Signed<DispatchPermit>> {
        let digest = request_digest(Action::Seal, binding)?;
        let mut result = None;
        self.mutate(fence, trusted_now_unix_ms, |tx, now| {
            replayed_command(tx, command_id, Action::Seal, &digest)?;
            let row = required(tx, &binding.slot_id)?;
            let allocation_hash = allocation_digest(tx, &row)?;
            let retained = retained_permit(tx, &row.slot.id)?;
            let fresh = retained.is_none();
            let permit = transition::seal(&row, &allocation_hash, binding, retained, now, issuer)?;
            result = Some(permit.clone());
            bind_command(tx, command_id, Action::Seal, &digest, &row.slot.id)?;
            if !fresh {
                return Ok(None);
            }
            tx.execute(
                "INSERT INTO work_delegation_permits (slot_id, permit) VALUES (?1, ?2)",
                params![row.slot.id, encode(&permit)?],
            )
            .map_err(sqlite_error)?;
            mark_dispatched(tx, &row.slot.id)?;
            let mut updated = row;
            updated.dispatched = true;
            Ok(Some((command_id.to_owned(), vec![updated])))
        })?;
        result.ok_or_else(|| invalid("seal produced no permit"))
    }

    /// Authorized history read of a retained permit. It verifies the stored
    /// bytes against their exact binding and the configured issuer but grants
    /// no fresh liveness. An absent permit stays absent.
    pub fn historical_dispatch(
        &self,
        binding: &DispatchBinding,
        issuer: &PublicKey,
    ) -> Result<Option<Signed<DispatchPermit>>> {
        self.read_only(|tx| {
            let Some(row) = read(tx, &binding.slot_id)? else {
                return Ok(None);
            };
            let Some(permit) = retained_permit(tx, &row.slot.id)? else {
                return Ok(None);
            };
            let allocation_hash = allocation_digest(tx, &row)?;
            transition::verify_historical_permit(&permit, &row, &allocation_hash, binding, issuer)?;
            Ok(Some(permit))
        })
    }

    fn connection(&self) -> Result<StoreGuard<'_>> {
        self.connection
            .lock()
            .map_err(|error| SqliteDelegationStoreError::Unavailable(error.to_string()))
    }

    fn read_only<T>(&self, read: impl FnOnce(&Transaction<'_>) -> Result<T>) -> Result<T> {
        let mut connection = self.connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        verify_active_owner(&tx, &self.serving_owner, None).map_err(unavailable)?;
        self.serving_owner
            .verify_authority_anchor(&tx)
            .map_err(unavailable)?;
        read(&tx)
    }

    /// Run one fenced mutation. The closure returns every slot state it
    /// changed, keyed by the command that changed them, or `None` for a replay
    /// that changes no slot. Each changed slot is one event and one global
    /// authority commit; a command binding alone is committed without either.
    fn mutate(
        &self,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
        apply: impl FnOnce(&Transaction<'_>, u64) -> Result<Option<(String, Vec<SlotState>)>>,
    ) -> Result<()> {
        let mut connection = self.connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence)).map_err(unavailable)?;
        self.serving_owner
            .verify_authority_anchor(&tx)
            .map_err(unavailable)?;
        verify_trusted_time(&tx, trusted_now_unix_ms, &self.serving_owner).map_err(unavailable)?;
        if let Some((command_id, changed)) = apply(&tx, trusted_now_unix_ms / 1000)? {
            let mutation = format!("work_delegation_{}", command_action(&tx, &command_id)?);
            for row in &changed {
                let sequence = append_event(&tx, &command_id, row)?;
                self.serving_owner
                    .append_global_commit(
                        &tx,
                        &mutation,
                        PROJECTION,
                        schema::PROJECTION_KEY,
                        sequence,
                    )
                    .map_err(unavailable)?;
            }
        }
        tx.commit().map_err(|error| {
            SqliteDelegationStoreError::Unavailable(
                self.serving_owner
                    .outcome_unknown(format!("sqlite delegation commit is unknown: {error}"))
                    .to_string(),
            )
        })?;
        self.serving_owner
            .sync_authority_anchor(&connection)
            .map_err(unavailable)
    }
}

fn request_digest(action: Action, request: &impl Serialize) -> Result<String> {
    let bytes = chio_core::canonical::canonical_json_bytes(&(
        "chio.work-delegation-command.v1",
        action.as_str(),
        request,
    ))
    .map_err(|error| invalid(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Whether `command_id` is already bound to exactly this request. A binding
/// to any other action or body is a conflict.
fn replayed_command(
    tx: &Transaction<'_>,
    command_id: &str,
    action: Action,
    digest: &str,
) -> Result<bool> {
    let retained: Option<(String, String)> = tx
        .query_row(
            "SELECT action, request_digest FROM work_delegation_commands WHERE command_id = ?1",
            [command_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    match retained {
        Some((retained_action, retained_digest)) => {
            if retained_action != action.as_str() || retained_digest != digest {
                return Err(SqliteDelegationStoreError::CommandConflict);
            }
            Ok(true)
        }
        None => Ok(false),
    }
}

fn bind_command(
    tx: &Transaction<'_>,
    command_id: &str,
    action: Action,
    digest: &str,
    slot_id: &str,
) -> Result<()> {
    if replayed_command(tx, command_id, action, digest)? {
        return Ok(());
    }
    tx.execute(
        "INSERT INTO work_delegation_commands (command_id, action, request_digest, slot_id)
         VALUES (?1, ?2, ?3, ?4)",
        params![command_id, action.as_str(), digest, slot_id],
    )
    .map_err(sqlite_error)?;
    Ok(())
}

fn command_action(tx: &Transaction<'_>, command_id: &str) -> Result<String> {
    tx.query_row(
        "SELECT action FROM work_delegation_commands WHERE command_id = ?1",
        [command_id],
        |row| row.get(0),
    )
    .map_err(sqlite_error)
}

pub(super) fn state_digest(row: &SlotState) -> Result<String> {
    let bytes = chio_core::canonical::canonical_json_bytes(&(
        "chio.work-delegation-state.v1",
        &row.slot,
        &row.parent,
        &row.root,
        row.allocated,
        &row.selection,
        row.revision,
        row.dispatched,
    ))
    .map_err(|error| invalid(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn append_event(tx: &Transaction<'_>, command_id: &str, row: &SlotState) -> Result<u64> {
    let previous: i64 = tx
        .query_row(
            "SELECT COALESCE(MAX(sequence), 0) FROM work_delegation_events",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let sequence = u64::try_from(previous)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| invalid("delegation event sequence overflow"))?;
    tx.execute(
        "INSERT INTO work_delegation_events (sequence, command_id, slot_id, state_digest)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            sql_u64(sequence)?,
            command_id,
            row.slot.id,
            state_digest(row)?
        ],
    )
    .map_err(sqlite_error)?;
    Ok(sequence)
}

fn insert(tx: &Transaction<'_>, row: &SlotState) -> Result<()> {
    tx.execute(
        "INSERT INTO work_delegation_slots
             (slot_id, parent_id, root_id, slot, allocated, selection, revision, dispatched)
         VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, 0)",
        params![
            row.slot.id,
            row.parent,
            row.root,
            encode(&row.slot)?,
            sql_u64(row.allocated)?,
            sql_u64(row.revision)?,
        ],
    )
    .map_err(sqlite_error)?;
    Ok(())
}

fn mark_dispatched(tx: &Transaction<'_>, slot_id: &str) -> Result<()> {
    tx.execute(
        "UPDATE work_delegation_slots SET dispatched = 1 WHERE slot_id = ?1",
        [slot_id],
    )
    .map_err(sqlite_error)?;
    Ok(())
}

fn retained_permit(
    connection: &Connection,
    slot_id: &str,
) -> Result<Option<Signed<DispatchPermit>>> {
    connection
        .query_row(
            "SELECT permit FROM work_delegation_permits WHERE slot_id = ?1",
            [slot_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sqlite_error)?
        .map(|text| decode(&text))
        .transpose()
}

pub(super) fn read(connection: &Connection, id: &str) -> Result<Option<SlotState>> {
    let raw = connection
        .query_row(
            "SELECT slot, parent_id, root_id, allocated, selection, revision, dispatched
             FROM work_delegation_slots WHERE slot_id = ?1",
            [id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(
        |(slot, parent, root, allocated, selection, revision, dispatched)| {
            let slot: WorkSlot = decode(&slot)?;
            if slot.id != id {
                return Err(invalid("stored slot identity"));
            }
            let state = SlotState {
                slot,
                parent,
                root,
                allocated: u64::try_from(allocated).map_err(|_| invalid("stored allocation"))?,
                selection: selection.map(|text| decode(&text)).transpose()?,
                revision: u64::try_from(revision).map_err(|_| invalid("stored revision"))?,
                dispatched: dispatched == 1,
            };
            state.validate()?;
            Ok(state)
        },
    )
    .transpose()
}

fn required(connection: &Connection, id: &str) -> Result<SlotState> {
    read(connection, id)?.ok_or_else(|| DelegationError::Invalid("unknown work slot".into()).into())
}

fn count(connection: &Connection, column: &str, id: &str) -> Result<u64> {
    let sql = match column {
        "parent_id" => "SELECT COUNT(*) FROM work_delegation_slots WHERE parent_id = ?1",
        "root_id" => "SELECT COUNT(*) FROM work_delegation_slots WHERE root_id = ?1",
        _ => return Err(invalid("unsupported count column")),
    };
    let value: i64 = connection
        .query_row(sql, [id], |row| row.get(0))
        .map_err(sqlite_error)?;
    u64::try_from(value).map_err(|_| invalid("slot count"))
}

pub(super) fn namespace(connection: &Connection) -> Result<String> {
    connection
        .query_row(
            "SELECT namespace FROM work_delegation_namespace WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or_else(|| invalid("delegation namespace is absent"))
}

fn allocation_digest(connection: &Connection, row: &SlotState) -> Result<String> {
    let root = required(connection, &row.root)?;
    Ok(transition::allocation_digest(
        &namespace(connection)?,
        &root,
        row,
    )?)
}

fn encode(value: &impl Serialize) -> Result<String> {
    let bytes = chio_core::canonical::canonical_json_bytes(value)
        .map_err(|error| invalid(error.to_string()))?;
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(DelegationError::Invalid("envelope byte limit".into()).into());
    }
    String::from_utf8(bytes).map_err(|error| invalid(error.to_string()))
}

fn decode<T: serde::de::DeserializeOwned>(text: &str) -> Result<T> {
    chio_core::canonical::UntrustedJsonText::from_wire(text.as_bytes(), MAX_ENVELOPE_BYTES)
        .and_then(|text| text.decode_signed())
        .map_err(|error| invalid(error.to_string()))
}

fn sql_u64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| invalid("integer exceeds SQLite range"))
}

fn sqlite_error(error: rusqlite::Error) -> SqliteDelegationStoreError {
    SqliteDelegationStoreError::Unavailable(error.to_string())
}

fn unavailable(error: impl std::fmt::Display) -> SqliteDelegationStoreError {
    SqliteDelegationStoreError::Unavailable(error.to_string())
}

fn invalid(detail: impl Into<String>) -> SqliteDelegationStoreError {
    SqliteDelegationStoreError::Invalid(detail.into())
}

pub(super) fn owner_invalid(detail: impl Into<String>) -> SqliteServingOwnerError {
    SqliteServingOwnerError::Invalid(detail.into())
}
