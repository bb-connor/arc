//! Physical amounts describe a bounded write. They never grant a writer loan.
use super::*;
use serde::{Deserialize, Serialize};

mod connection_namespace;
mod native_join_pricing;
mod preservation;
mod raw_custody_pricing;
mod tool_outcome_pricing;
#[cfg(test)]
pub(in crate::admission_operation_store) use raw_custody_pricing::price_raw_custody_liability;
pub(in crate::admission_operation_store) use raw_custody_pricing::raw_custody_price_algorithm_fingerprint;
pub(in crate::admission_operation_store) use tool_outcome_pricing::{
    price_native_tool_outcome_phases, tool_outcome_price_algorithm_fingerprint,
};
mod pricing;
#[cfg(test)]
use preservation::require_progress_preserving_liability;
pub(in crate::admission_operation_store) use pricing::physical_command_write_profile;
pub(in crate::admission_operation_store) use pricing::price_protected_command_liability;
pub(in crate::admission_operation_store) use pricing::price_protected_command_with_row_limits;

// Exact shared SQLite engine cost bounds owned once for the frame pricers.
// The bundled SQLite cursor has at most20 levels. balance_nonroot retains at
// most3 old siblings, allocates at most5 resulting siblings, and dirties their
// parent. Their union plus parent is at most6 pages at each traversed level.
const CURSOR_LEVELS: u64 = 20;
const BALANCE_PAGES_PER_LEVEL: u64 = 6;
const NEW_BALANCE_WALKS: u64 = 1;
const EXISTING_BALANCE_WALKS: u64 = 3;
const ALLOCATION_OR_FREE_FRAME_MULTIPLIER: u64 = 2;
const FRAME_HEADER_BYTES: u64 = 24;
const WAL_HEADER_BYTES: u64 = 32;
// sqlite3SectorSize clamps the actual WAL sector size to this compiled bound.
// Always price padding, including when a previously opened WAL cached a device
// property different from the current main file's powersafe-overwrite flag.
const MAX_WAL_SECTOR_BYTES: u64 = 65_536;
// The fixed serving anchor file is retained whole as a conservative margin.
const SERVING_ANCHOR_FILE_BYTES: u64 = 2 * 1_024;

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store) struct PhysicalLiabilityData {
    wal_bytes: u64,
    disk_bytes: u64,
    recovery_appends: u64,
    global_appends: u64,
}

impl PhysicalLiabilityData {
    pub(in crate::admission_operation_store) fn zero() -> Self {
        Self::default()
    }

    /// One priced transaction on the native authority file. Like every native
    /// frame price it retains the whole serving anchor as a disk margin.
    pub(in crate::admission_operation_store) fn native_transaction(
        wal_bytes: u64,
        disk_bytes: u64,
        recovery_appends: u64,
        global_appends: u64,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let amount = Self {
            wal_bytes,
            disk_bytes: disk_bytes
                .checked_add(SERVING_ANCHOR_FILE_BYTES)
                .ok_or_else(|| invariant("native transaction anchor disk bound exhausted"))?,
            recovery_appends,
            global_appends,
        };
        amount.validate()?;
        Ok(amount)
    }

    /// A priced write on another registered file. It appends nothing to
    /// this authority's recovery history or global chain.
    pub(in crate::admission_operation_store) fn registered_file(
        wal_bytes: u64,
        disk_bytes: u64,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let amount = Self {
            wal_bytes,
            disk_bytes,
            recovery_appends: 0,
            global_appends: 0,
        };
        amount.validate()?;
        Ok(amount)
    }

    pub(in crate::admission_operation_store) fn wal_bytes(&self) -> u64 {
        self.wal_bytes
    }

    pub(in crate::admission_operation_store) fn disk_bytes(&self) -> u64 {
        self.disk_bytes
    }

    pub(in crate::admission_operation_store) fn recovery_appends(&self) -> u64 {
        self.recovery_appends
    }

    pub(in crate::admission_operation_store) fn global_appends(&self) -> u64 {
        self.global_appends
    }

    pub(in crate::admission_operation_store) fn checked_add(
        &self,
        other: &Self,
    ) -> Result<Self, AdmissionOperationStoreError> {
        self.combine(other, u64::checked_add)
    }

    pub(in crate::admission_operation_store) fn checked_sub(
        &self,
        other: &Self,
    ) -> Result<Self, AdmissionOperationStoreError> {
        self.combine(other, u64::checked_sub)
    }

    fn combine(
        &self,
        other: &Self,
        operation: fn(u64, u64) -> Option<u64>,
    ) -> Result<Self, AdmissionOperationStoreError> {
        self.validate()?;
        other.validate()?;
        let amount = Self {
            wal_bytes: operation(self.wal_bytes, other.wal_bytes)
                .ok_or_else(|| invariant("physical WAL liability exhausted"))?,
            disk_bytes: operation(self.disk_bytes, other.disk_bytes)
                .ok_or_else(|| invariant("physical disk liability exhausted"))?,
            recovery_appends: operation(self.recovery_appends, other.recovery_appends)
                .ok_or_else(|| invariant("physical recovery append liability exhausted"))?,
            global_appends: operation(self.global_appends, other.global_appends)
                .ok_or_else(|| invariant("physical global append liability exhausted"))?,
        };
        amount.validate()?;
        Ok(amount)
    }

    fn validate(&self) -> Result<(), AdmissionOperationStoreError> {
        if self.recovery_appends > MAX_TRUSTED_UNIX_MS
            || self.global_appends > MAX_TRUSTED_UNIX_MS
            || self.disk_bytes < self.wal_bytes
        {
            return Err(invariant("physical liability data is outside its profile"));
        }
        Ok(())
    }
}

#[derive(Default)]
pub(in crate::admission_operation_store) struct ProtectedCommandLiabilityPlan {
    commands: Vec<PlannedCommand>,
}

struct PlannedCommand {
    key: String,
    scope: String,
    max_payload_bytes: u64,
    source: Option<ExistingCommandData>,
    rewrite: bool,
}

struct ExistingCommandData {
    version: u64,
    digest: ProjectionDigest,
    event_sequence: u64,
    global_commit_sequence: u64,
}

impl ProtectedCommandLiabilityPlan {
    pub(in crate::admission_operation_store) fn new() -> Self {
        Self::default()
    }

    pub(in crate::admission_operation_store) fn add_new_command(
        &mut self,
        tx: &Connection,
        key: &str,
        scope: &str,
        max_payload_bytes: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        let command = PlannedCommand {
            key: key.to_owned(),
            scope: scope.to_owned(),
            max_payload_bytes,
            source: None,
            rewrite: false,
        };
        command.verify(tx)?;
        self.require_next_command()?;
        self.commands.push(command);
        Ok(())
    }

    /// Price one later rewrite of a typed command its writer owns. The header
    /// may still be pristine; the priced shape is the existing-row update with
    /// its old and new overflow images, never the cheaper pristine insert.
    pub(in crate::admission_operation_store) fn add_owned_rewrite(
        &mut self,
        tx: &Connection,
        key: &str,
        scope: &str,
        max_payload_bytes: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        let command = PlannedCommand {
            key: key.to_owned(),
            scope: scope.to_owned(),
            max_payload_bytes,
            source: None,
            rewrite: true,
        };
        command.verify(tx)?;
        self.require_next_command()?;
        self.commands.push(command);
        Ok(())
    }

    pub(in crate::admission_operation_store) fn add_existing_command(
        &mut self,
        tx: &Connection,
        source: &ProtectedSourceReference,
        max_payload_bytes: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        connection_namespace::require_command_namespace(tx)?;
        if source.kind() != "command" {
            return Err(invariant("physical command plan changed its source kind"));
        }
        verify_source_reference(tx, source)?;
        let command = PlannedCommand {
            key: source.record_key().to_owned(),
            scope: source.scope_key().to_owned(),
            max_payload_bytes,
            source: Some(ExistingCommandData {
                version: source.version(),
                digest: *source.digest(),
                event_sequence: source.event_sequence(),
                global_commit_sequence: source.global_commit_sequence(),
            }),
            rewrite: false,
        };
        command.verify(tx)?;
        self.require_next_command()?;
        self.commands.push(command);
        Ok(())
    }

    fn require_next_command(&self) -> Result<(), AdmissionOperationStoreError> {
        if self.commands.len() >= MAX_RECOVERY_BATCH {
            return Err(invariant("physical command plan exceeds its bounded batch"));
        }
        Ok(())
    }
}

impl PlannedCommand {
    fn verify(&self, tx: &Connection) -> Result<(), AdmissionOperationStoreError> {
        connection_namespace::require_command_namespace(tx)?;
        if self.key.is_empty()
            || self.key.chars().count() > 512
            || self.key.len() > 2048
            || self.key.contains('\0')
            || self.scope.len() != 64
            || !self.scope.bytes().all(|byte| byte.is_ascii_hexdigit())
            || self.max_payload_bytes == 0
            || self.max_payload_bytes
                > u64::try_from(MAX_RECOVERY_RECORD_BYTES)
                    .map_err(|_| invariant("physical command payload bound refused"))?
        {
            return Err(invariant(
                "physical command descriptor is outside its profile",
            ));
        }
        let current = raw_checked(tx, &self.key)?;
        if self.rewrite {
            return match current {
                None => Ok(()),
                Some(row)
                    if row.kind == "command"
                        && row.scope == self.scope
                        && u64::try_from(row.payload.len())
                            .map_err(|_| invariant("physical source bytes refused"))?
                            <= self.max_payload_bytes =>
                {
                    Ok(())
                }
                Some(_) => Err(invariant("physical owned rewrite changed its typed header")),
            };
        }
        match (&self.source, current) {
            (None, None) => Ok(()),
            (Some(expected), Some(row)) => {
                let source = source_reference(tx, &self.key)?;
                let native: bool = tx
                    .query_row(
                        "SELECT native_namespace IS NOT NULL OR native_request IS NOT NULL
                     FROM main.admission_operation_recovery_records WHERE record_key=?1",
                        [&self.key],
                        |row| row.get(0),
                    )
                    .map_err(sqlite_error)?;
                if row.kind != "command"
                    || row.scope != self.scope
                    || native
                    || u64::try_from(row.payload.len())
                        .map_err(|_| invariant("physical source bytes refused"))?
                        > self.max_payload_bytes
                    || source.version() != expected.version
                    || *source.digest() != expected.digest
                    || source.event_sequence() != expected.event_sequence
                    || source.global_commit_sequence() != expected.global_commit_sequence
                {
                    return Err(invariant(
                        "physical command plan lost its exact current source",
                    ));
                }
                Ok(())
            }
            _ => Err(invariant(
                "physical command plan changed its pristine or retained header",
            )),
        }
    }
}

#[cfg(test)]
mod tests;
