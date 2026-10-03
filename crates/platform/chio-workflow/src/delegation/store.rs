use super::{types::*, DelegationError as Error, Result};
use chio_core::crypto::PublicKey;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::{
    path::Path,
    sync::{Mutex, MutexGuard},
    time::Duration,
};

/// Protected owner-local allocation service. Callers must not share or roll back
/// its database independently of native operation custody. No allocation release
/// API exists: ambiguous work retains its full ceiling.
pub struct DelegationStore {
    connection: Mutex<Connection>,
}

struct Row {
    slot: WorkSlot,
    parent: Option<String>,
    root: String,
    allocated: u64,
    selection: Option<Signed<Selection>>,
    revision: u64,
    dispatched: bool,
}

impl DelegationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS work_slots_v1 (
                id TEXT PRIMARY KEY, parent TEXT REFERENCES work_slots_v1(id),
                root TEXT NOT NULL, body TEXT NOT NULL, allocated TEXT NOT NULL,
                selection TEXT, revision INTEGER NOT NULL, dispatched INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS work_slots_parent_v1 ON work_slots_v1(parent);
            CREATE INDEX IF NOT EXISTS work_slots_root_v1 ON work_slots_v1(root);",
        )?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection.lock().map_err(|_| Error::Unavailable)
    }

    /// Trusted owner configuration only. This does not verify an end-user grant.
    pub fn create_root(&self, slot: WorkSlot) -> Result<()> {
        slot.validate()?;
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(row) = read(&tx, &slot.id)? {
            if row.parent.is_some() || row.slot != slot {
                return Err(Error::Conflict);
            }
        } else {
            insert(&tx, &slot, None, &slot.id)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn slot(&self, id: &str) -> Result<WorkSlot> {
        let connection = self.connection()?;
        Ok(required(&connection, id)?.slot)
    }

    pub fn subdivide(&self, request: &Signed<Subdivision>, now: u64) -> Result<WorkSlot> {
        request.verify()?;
        request.body.child.validate()?;
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let parent = required(&tx, &request.body.parent_id)?;
        if request.signer != parent.slot.holder {
            return Err(Error::Authority);
        }
        live(parent.slot.contract.expires_at, now)?;
        live(request.body.child.contract.expires_at, now)?;
        parent
            .slot
            .contract
            .permits_child(&request.body.child.contract)?;
        if parent.selection.is_some() {
            return Err(Error::Conflict);
        }
        if let Some(existing) = read(&tx, &request.body.child.id)? {
            if existing.slot != request.body.child
                || existing.parent.as_ref() != Some(&parent.slot.id)
            {
                return Err(Error::Conflict);
            }
            return Ok(existing.slot);
        }
        let allocated = parent
            .allocated
            .checked_add(request.body.child.contract.max_units)
            .ok_or(Error::Bounds)?;
        if allocated > parent.slot.contract.max_units {
            return Err(Error::Bounds);
        }
        let count: i64 = tx.query_row(
            "SELECT count(*) FROM work_slots_v1 WHERE parent=?1",
            [&parent.slot.id],
            |r| r.get(0),
        )?;
        let root_count: i64 = tx.query_row(
            "SELECT count(*) FROM work_slots_v1 WHERE root=?1",
            [&parent.root],
            |r| r.get(0),
        )?;
        if count >= 64 || root_count >= 4096 {
            return Err(Error::Bounds);
        }
        insert(
            &tx,
            &request.body.child,
            Some(&parent.slot.id),
            &parent.root,
        )?;
        tx.execute(
            "UPDATE work_slots_v1 SET allocated=?1 WHERE id=?2",
            params![allocated.to_string(), parent.slot.id],
        )?;
        tx.commit()?;
        Ok(request.body.child.clone())
    }

    /// Enrollment is trusted local configuration, never a field from an offer.
    pub fn select(
        &self,
        request: &Signed<Selection>,
        now: u64,
        qualified: &[PublicKey],
    ) -> Result<()> {
        request.verify()?;
        let selection = &request.body;
        selection.offer.verify()?;
        identifier(&selection.request_id)?;
        hash(&selection.capability_hash)?;
        let offer = &selection.offer.body;
        hash(&offer.arguments_hash)?;
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = required(&tx, &offer.slot_id)?;
        if request.signer != row.slot.holder
            || selection.offer.signer != offer.receiver
            || !qualified.contains(&offer.receiver)
            || !row.slot.contract.readers.contains(&offer.receiver.to_hex())
        {
            return Err(Error::Authority);
        }
        live(row.slot.contract.expires_at, now)?;
        live(offer.expires_at, now)?;
        if offer.expires_at > row.slot.contract.expires_at
            || offer.price_units > row.slot.contract.max_units
            || !row.slot.contract.effects.contains(&offer.effect)
        {
            return Err(Error::Bounds);
        }
        let children: i64 = tx.query_row(
            "SELECT count(*) FROM work_slots_v1 WHERE parent=?1",
            [&row.slot.id],
            |r| r.get(0),
        )?;
        if children != 0 {
            return Err(Error::Conflict);
        }
        if row.selection.as_ref() == Some(request) {
            return Ok(());
        }
        if row.dispatched || selection.expected_revision != row.revision {
            return Err(Error::Conflict);
        }
        let next = row
            .revision
            .checked_add(1)
            .filter(|n| *n <= MAX_UNITS)
            .ok_or(Error::Bounds)?;
        tx.execute(
            "UPDATE work_slots_v1 SET selection=?1,revision=?2 WHERE id=?3",
            params![
                encode(request)?,
                i64::try_from(next).map_err(|_| Error::Bounds)?,
                row.slot.id
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Irreversible allocation claim. Native operation replay is a separate,
    /// required boundary; idempotence here is not permission to repeat an effect.
    pub fn claim_dispatch(&self, binding: &DispatchBinding, now: u64) -> Result<Admission> {
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = required(&tx, &binding.slot_id)?;
        let selection = row.selection.ok_or(Error::Conflict)?;
        let offer = &selection.body.offer.body;
        live(row.slot.contract.expires_at, now)?;
        live(offer.expires_at, now)?;
        if binding.subject != row.slot.holder || binding.receiver != offer.receiver {
            return Err(Error::Authority);
        }
        if binding.request_id != selection.body.request_id
            || binding.capability_hash != selection.body.capability_hash
            || binding.arguments_hash != offer.arguments_hash
            || binding.effect != offer.effect
        {
            return Err(Error::Conflict);
        }
        if binding.currency != row.slot.contract.currency || binding.max_units > offer.price_units {
            return Err(Error::Bounds);
        }
        tx.execute(
            "UPDATE work_slots_v1 SET dispatched=1 WHERE id=?1",
            [&row.slot.id],
        )?;
        tx.commit()?;
        Ok(Admission {
            slot: row.slot,
            selection,
        })
    }
}

fn encode(value: &impl serde::Serialize) -> Result<String> {
    String::from_utf8(canonical(value)?).map_err(|e| Error::Invalid(e.to_string()))
}
fn insert(
    connection: &Connection,
    slot: &WorkSlot,
    parent: Option<&str>,
    root: &str,
) -> Result<()> {
    connection.execute("INSERT INTO work_slots_v1(id,parent,root,body,allocated,revision,dispatched) VALUES(?1,?2,?3,?4,'0',0,0)",
        params![slot.id, parent, root, encode(slot)?])?;
    Ok(())
}
fn read(connection: &Connection, id: &str) -> Result<Option<Row>> {
    let raw = connection.query_row("SELECT body,parent,root,allocated,selection,revision,dispatched FROM work_slots_v1 WHERE id=?1", [id], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, String>(2)?,
            r.get::<_, String>(3)?, r.get::<_, Option<String>>(4)?, r.get::<_, i64>(5)?, r.get::<_, u8>(6)?))
    }).optional()?;
    raw.map(
        |(body, parent, root, allocated, selection, revision, dispatched)| {
            let slot: WorkSlot =
                serde_json::from_str(&body).map_err(|e| Error::Invalid(e.to_string()))?;
            slot.validate()?;
            if slot.id != id || dispatched > 1 {
                return invalid("stored slot identity/state");
            }
            let revision = u64::try_from(revision).map_err(|_| Error::Conflict)?;
            let allocated = allocated
                .parse::<u64>()
                .map_err(|e| Error::Invalid(e.to_string()))?;
            if allocated > slot.contract.max_units {
                return invalid("stored allocation");
            }
            let selection = selection
                .map(|s| serde_json::from_str(&s).map_err(|e| Error::Invalid(e.to_string())))
                .transpose()?;
            Ok(Row {
                slot,
                parent,
                root,
                allocated,
                selection,
                revision,
                dispatched: dispatched == 1,
            })
        },
    )
    .transpose()
}
fn required(connection: &Connection, id: &str) -> Result<Row> {
    read(connection, id)?.ok_or_else(|| Error::Invalid("unknown work slot".into()))
}
