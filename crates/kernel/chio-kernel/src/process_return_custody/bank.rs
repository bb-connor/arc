//! Narrow bank observations. None of these values is an actual-purpose loan.
use super::*;

pub const PROCESS_RETURN_INVENTORY_SCHEMA: &str = "chio.process-return-inventory.v1";
pub const PROCESS_RETURN_BANK_READBACK_SCHEMA: &str = "chio.process-return-bank-readback.v1";

/// Complete file observation, including every root, retained account and
/// current writer. Counts never stand in for the owning full-content inverse.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessReturnInventoryDataV1 {
    pub schema: String,
    pub journal_namespace: String,
    pub journal_authority: String,
    pub kernel_key_digest: String,
    pub file_device: u64,
    pub file_inode: u64,
    pub catalog_digest: String,
    pub physical_profile_digest: String,
    pub whole_source_cut_digest: String,
    pub roots_digest: String,
    pub root_count: u64,
    pub process_count: u64,
    pub account_count: u64,
    pub phase_count: u64,
    pub current_write_count: u64,
    pub history_sequence: u64,
    pub history_digest: String,
}
impl ProcessReturnInventoryDataV1 {
    pub fn validate_data(&self) -> Result<(), AdmissionOperationStoreError> {
        if self.schema != PROCESS_RETURN_INVENTORY_SCHEMA
            || !uuid_text(&self.journal_namespace)
            || !uuid_text(&self.journal_authority)
            || self.file_inode == 0
            || self.root_count > self.process_count
            || [
                self.root_count,
                self.process_count,
                self.account_count,
                self.phase_count,
                self.current_write_count,
                self.history_sequence,
            ]
            .iter()
            .any(|n| *n > MAX_SEQUENCE)
        {
            return Err(unavailable());
        }
        for value in [
            &self.kernel_key_digest,
            &self.catalog_digest,
            &self.physical_profile_digest,
            &self.whole_source_cut_digest,
            &self.roots_digest,
            &self.history_digest,
        ] {
            require_digest(value)?;
        }
        Ok(())
    }
}

/// The absent default is exclusively the old v1 wire spelling. No source or
/// funding constructor accepts that absence as a committed publication.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessNativeAccountPublicationDataV1 {
    pub schema: String,
    pub record_key: String,
    pub scope_key: String,
    pub record_kind: String,
    pub record_version: u64,
    pub record_digest: String,
    pub event_sequence: u64,
    pub global_commit_sequence: u64,
    pub original_source_cut: u64,
    pub authority_global_sequence_domain: NativeReturnSequenceDomainDataV1,
}
impl ProcessNativeAccountPublicationDataV1 {
    pub fn is_absent(&self) -> bool {
        self == &Self::default()
    }
    pub fn validate(&self) -> Result<(), AdmissionOperationStoreError> {
        if self.schema != "chio.native-finishing-prepared-publication.v1" {
            return Err(unavailable());
        }
        validate_publication(
            PublicationRecordRef {
                key: &self.record_key,
                scope: &self.scope_key,
                kind: &self.record_kind,
                version: self.record_version,
                record_digest: &self.record_digest,
            },
            self.event_sequence,
            self.global_commit_sequence,
            self.original_source_cut,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessCurrentWritePublicationDataV1 {
    pub schema: String,
    pub record_key: String,
    pub scope_key: String,
    pub record_kind: String,
    pub record_version: u64,
    pub record_digest: String,
    pub event_sequence: u64,
    pub global_commit_sequence: u64,
    pub original_source_cut: u64,
    pub authority_global_sequence_domain: NativeReturnSequenceDomainDataV1,
}
impl ProcessCurrentWritePublicationDataV1 {
    pub fn validate_data(&self) -> Result<(), AdmissionOperationStoreError> {
        if self.schema != "chio.native-process-current-write-publication.v1"
            || !self
                .record_key
                .starts_with("native-process-current-intent:")
        {
            return Err(unavailable());
        }
        require_digest(
            self.record_key
                .trim_start_matches("native-process-current-intent:"),
        )?;
        validate_publication(
            PublicationRecordRef {
                key: &self.record_key,
                scope: &self.scope_key,
                kind: &self.record_kind,
                version: self.record_version,
                record_digest: &self.record_digest,
            },
            self.event_sequence,
            self.global_commit_sequence,
            self.original_source_cut,
        )
    }
}
struct PublicationRecordRef<'a> {
    key: &'a str,
    scope: &'a str,
    kind: &'a str,
    version: u64,
    record_digest: &'a str,
}

fn validate_publication(
    record: PublicationRecordRef<'_>,
    event: u64,
    global: u64,
    cut: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let PublicationRecordRef {
        key,
        scope,
        kind,
        version,
        record_digest,
    } = record;
    if key.is_empty()
        || key.len() > 256
        || key.chars().any(char::is_control)
        || kind != "command"
        || version != 1
        || !positive_sequence(event)
        || !positive_sequence(global)
        || global <= cut
    {
        return Err(unavailable());
    }
    require_digest(scope)?;
    require_digest(record_digest)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessReturnBankReadbackDataV1 {
    pub schema: String,
    pub inventory_digest: String,
    pub native_bank_epoch: u64,
    pub native_frontier_digest: String,
    pub registered_files_digest: String,
    pub same_filesystem_other_disk_bytes: u64,
    pub this_file_reserved_wal_bytes: u64,
    pub this_file_reserved_disk_bytes: u64,
    pub this_file_reserved_wal_frames: u64,
    pub current_write_publication: Option<ProcessCurrentWritePublicationDataV1>,
}

/// Affine evidence of a configured owner's bank readback. A Process writer
/// additionally needs its actual-purpose lender, complete capacity and current
/// request authority. This proof deliberately exposes no spend/commit method.
pub struct VerifiedProcessReturnBank {
    inventory: ProcessReturnInventoryDataV1,
    readback: ProcessReturnBankReadbackDataV1,
    fence: StoreMutationFence,
    trusted_now_unix_ms: u64,
    scope_generation: u64,
    owner_identity: usize,
}
impl VerifiedProcessReturnBank {
    pub(crate) fn from_scoped_owner(
        port: &dyn NativeProcessReturnCustodyPort,
        inventory: &ProcessReturnInventoryDataV1,
        fence: &StoreMutationFence,
        now: u64,
        scope_generation: u64,
        owner_identity: usize,
    ) -> Result<Self, AdmissionOperationStoreError> {
        inventory.validate_data()?;
        if inventory.journal_authority != fence.store_uuid {
            return Err(unavailable());
        }
        let readback = port.verify_original_process_return_inventory(inventory, fence, now)?;
        if readback.schema != PROCESS_RETURN_BANK_READBACK_SCHEMA
            || readback.inventory_digest
                != digest(&bounded_bytes(inventory, MAX_PROCESS_RETURN_SOURCE_BYTES)?)
            || !positive_sequence(readback.native_bank_epoch)
            || readback.this_file_reserved_disk_bytes < readback.this_file_reserved_wal_bytes
            || (readback.this_file_reserved_wal_frames == 0)
                != (readback.this_file_reserved_wal_bytes == 0)
        {
            return Err(unavailable());
        }
        require_digest(&readback.native_frontier_digest)?;
        require_digest(&readback.registered_files_digest)?;
        if let Some(publication) = &readback.current_write_publication {
            publication.validate_data()?;
            if publication.global_commit_sequence > readback.native_bank_epoch {
                return Err(unavailable());
            }
        }
        Ok(Self {
            inventory: inventory.clone(),
            readback,
            fence: fence.clone(),
            trusted_now_unix_ms: now,
            scope_generation,
            owner_identity,
        })
    }
    pub(crate) fn issued_in_scope(&self, scope_generation: u64, owner_identity: usize) -> bool {
        self.scope_generation == scope_generation && self.owner_identity == owner_identity
    }
    pub fn inventory_data(&self) -> &ProcessReturnInventoryDataV1 {
        &self.inventory
    }
    pub fn readback_data(&self) -> &ProcessReturnBankReadbackDataV1 {
        &self.readback
    }
    pub fn fence_data(&self) -> &StoreMutationFence {
        &self.fence
    }
    pub fn observed_at_unix_ms(&self) -> u64 {
        self.trusted_now_unix_ms
    }
}
impl core::fmt::Debug for VerifiedProcessReturnBank {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("VerifiedProcessReturnBank([redacted])")
    }
}
