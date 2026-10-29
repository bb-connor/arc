#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable,
        clippy::dbg_macro,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::as_conversions,
    )
)]
//! External rollback generation anchor for SQLite stores.
//!
//! A [`RollbackGenerationAnchor`] keeps a monotonic store generation in a
//! private two-slot file outside the protected database. A store binds the
//! anchor once, verifies its own generation against the anchor on open and
//! before serving, and advances both through a prepare, operation and commit
//! sequence. A database image restored to an older generation no longer
//! matches the anchor and is refused.
//!
//! [`require_separate_snapshot_domain`] refuses an anchor root on the same
//! device as the database, since one filesystem snapshot could roll both back.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use chio_core::canonical::canonical_json_bytes;
use chio_core::sha256_hex;
use chio_sqlite_file_identity::custody::{self, read_exact_at, write_all_at};
use serde::{Deserialize, Serialize};

const SLOT_SIZE: usize = 512;
const SLOT_COUNT: usize = 2;
const FILE_SIZE: usize = SLOT_SIZE * SLOT_COUNT;
const COMMIT_MARKER: &[u8; 8] = b"CHIOG1OK";
const LENGTH_OFFSET: usize = COMMIT_MARKER.len();
const CHECKSUM_OFFSET: usize = LENGTH_OFFSET + 4;
const PAYLOAD_OFFSET: usize = CHECKSUM_OFFSET + 64;
const MAX_PAYLOAD_BYTES: usize = SLOT_SIZE - PAYLOAD_OFFSET;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GenerationRecord {
    anchor_instance_id: String,
    format: String,
    record_generation: u64,
    scope_sha256: String,
    store_generation: u64,
}

/// What a store head binds beyond its generation counter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "binding", content = "sha256", rename_all = "snake_case")]
pub enum AnchorHead {
    /// Lowercase sha256 hex of the store's content-binding history head.
    Chained(String),
    /// The store binds only its generation counter, so a fork that reaches
    /// the same generation with different content is not detected.
    CounterOnly,
}

/// A store's generation together with the head it binds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreHead {
    pub generation: u64,
    pub head: AnchorHead,
}

impl StoreHead {
    #[must_use]
    pub fn counter_only(generation: u64) -> Self {
        Self {
            generation,
            head: AnchorHead::CounterOnly,
        }
    }

    #[must_use]
    pub fn chained(generation: u64, head_sha256: impl Into<String>) -> Self {
        Self {
            generation,
            head: AnchorHead::Chained(head_sha256.into()),
        }
    }
}

struct LoadedRecord {
    record: GenerationRecord,
    prepared_record: Option<GenerationRecord>,
    corrupt_slot: bool,
    interrupted_slot: bool,
}

enum AnchorLoadState {
    Empty,
    PreparedInitial(GenerationRecord),
    Committed(LoadedRecord),
}

static PROCESS_ANCHOR_LOCKS: OnceLock<Mutex<BTreeMap<PathBuf, Weak<Mutex<()>>>>> = OnceLock::new();

/// Reject an anchor that can be rolled back by the same filesystem snapshot
/// as its protected SQLite database. A qualified anchor must cross a device
/// boundary; path separation alone is not a rollback boundary.
pub fn require_separate_snapshot_domain(
    database_path: &Path,
    anchor_root: &Path,
) -> Result<(), String> {
    let database_metadata = fs::metadata(database_path)
        .map_err(|error| format!("protected SQLite database metadata failed: {error}"))?;
    let anchor_metadata = fs::metadata(anchor_root)
        .map_err(|error| format!("rollback anchor root metadata failed: {error}"))?;
    if metadata_device(&database_metadata)? == metadata_device(&anchor_metadata)? {
        return Err(
            "rollback anchor root shares the protected database snapshot domain".to_string(),
        );
    }
    Ok(())
}

pub struct RollbackGenerationAnchor {
    file: File,
    root: PathBuf,
    path: PathBuf,
    expected_device: u64,
    expected_inode: u64,
    scope_sha256: String,
    process_lock: Arc<Mutex<()>>,
}

impl RollbackGenerationAnchor {
    pub fn open(root: &Path, scope: &[u8]) -> Result<Self, String> {
        validate_secure_root(root)?;
        let root = fs::canonicalize(root)
            .map_err(|error| format!("rollback anchor root is unavailable: {error}"))?;
        let scope_sha256 = sha256_hex(scope);
        let path = root.join(format!("{scope_sha256}.generation-anchor"));
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let (file, created) = match options.create_new(true).open(&path) {
            Ok(file) => (file, true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                options.create_new(false).create(false);
                let file = options
                    .open(&path)
                    .map_err(|error| format!("rollback anchor open failed: {error}"))?;
                (file, false)
            }
            Err(error) => return Err(format!("rollback anchor open failed: {error}")),
        };
        if created {
            File::open(&root)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("rollback anchor root sync failed: {error}"))?;
        }
        let metadata = file
            .metadata()
            .map_err(|error| format!("rollback anchor metadata failed: {error}"))?;
        validate_anchor_metadata(&metadata)?;
        let expected_device = metadata_device(&metadata)?;
        let expected_inode = metadata_inode(&metadata)?;
        let process_lock = process_anchor_lock(&path)?;
        let anchor = Self {
            file,
            root,
            path,
            expected_device,
            expected_inode,
            scope_sha256,
            process_lock,
        };
        anchor.validate_identity()?;
        Ok(anchor)
    }

    pub fn bind_initial_while(
        &self,
        load: impl FnOnce() -> Result<(StoreHead, bool), String>,
    ) -> Result<(), String> {
        self.with_lock(|| {
            let (store_head, allow_seed) = load()?;
            let store_generation = store_head.generation;
            match self.load_anchor_state()? {
                AnchorLoadState::Committed(loaded) => {
                    let loaded =
                        self.recover_prepared_for_store_generation(loaded, store_generation)?;
                    if loaded.corrupt_slot {
                        return Err("rollback anchor contains a corrupt slot".to_string());
                    }
                    self.validate_record(&loaded.record)?;
                    if loaded.interrupted_slot && loaded.record.store_generation != store_generation
                    {
                        return Err(
                            "interrupted rollback anchor does not match the store generation"
                                .to_string(),
                        );
                    }
                    if loaded.record.store_generation != store_generation {
                        return Err("store is behind its protected rollback generation".to_string());
                    }
                    Ok(())
                }
                AnchorLoadState::PreparedInitial(prepared)
                    if allow_seed
                        && store_generation == 0
                        && prepared.record_generation == 1
                        && prepared.store_generation == 0 =>
                {
                    self.commit_prepared(&prepared)
                }
                AnchorLoadState::PreparedInitial(_) => Err(
                    "prepared initial rollback anchor does not match an empty generation-zero store"
                        .to_string(),
                ),
                AnchorLoadState::Empty if allow_seed && store_generation == 0 => {
                    self.write_next(0, 0, &uuid::Uuid::now_v7().to_string())
                }
                AnchorLoadState::Empty => {
                    Err("protected rollback generation is absent".to_string())
                }
            }
        })
    }

    pub fn instance_id(&self) -> Result<String, String> {
        self.with_lock(|| {
            let loaded = self
                .load_record()?
                .ok_or_else(|| "protected rollback generation is absent".to_string())?;
            if loaded.corrupt_slot {
                return Err("rollback anchor contains a corrupt slot".to_string());
            }
            self.validate_record(&loaded.record)?;
            Ok(loaded.record.anchor_instance_id)
        })
    }

    pub fn verify(&self, store_head: &StoreHead) -> Result<(), String> {
        self.verify_while(|| Ok(store_head.clone()))
    }

    pub fn verify_while(
        &self,
        load: impl FnOnce() -> Result<StoreHead, String>,
    ) -> Result<(), String> {
        self.with_lock(|| {
            let store_generation = load()?.generation;
            let loaded = self
                .load_record()?
                .ok_or_else(|| "protected rollback generation is absent".to_string())?;
            let loaded = self.recover_prepared_for_store_generation(loaded, store_generation)?;
            if loaded.corrupt_slot {
                return Err("rollback anchor contains a corrupt slot".to_string());
            }
            self.validate_record(&loaded.record)?;
            if loaded.interrupted_slot && loaded.record.store_generation != store_generation {
                return Err(
                    "interrupted rollback anchor does not match the store generation".to_string(),
                );
            }
            if loaded.record.store_generation != store_generation {
                return Err("store does not match its protected rollback generation".to_string());
            }
            Ok(())
        })
    }

    pub fn advance_while(
        &self,
        expected: &StoreHead,
        next: &StoreHead,
        operation: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        let (expected, next) = (expected.generation, next.generation);
        if expected.checked_add(1) != Some(next) {
            return Err("rollback generation must advance by exactly one".to_string());
        }
        self.with_lock(|| {
            let loaded = self
                .load_record()?
                .ok_or_else(|| "protected rollback generation is absent".to_string())?;
            let loaded = self.recover_prepared_for_store_generation(loaded, expected)?;
            if loaded.corrupt_slot {
                return Err("rollback anchor contains a corrupt slot".to_string());
            }
            self.validate_record(&loaded.record)?;
            if loaded.record.store_generation != expected {
                return Err("rollback generation compare-and-advance failed".to_string());
            }
            let prepared = self.prepare_next(
                loaded.record.record_generation,
                next,
                &loaded.record.anchor_instance_id,
            )?;
            operation()?;
            self.commit_prepared(&prepared)
        })
    }

    fn with_lock<T>(&self, operation: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        let _process_guard = self
            .process_lock
            .lock()
            .map_err(|_| "rollback anchor process lock is poisoned".to_string())?;
        self.validate_identity()?;
        self.file
            .lock()
            .map_err(|error| format!("rollback anchor lock failed: {error}"))?;
        let result = operation();
        let unlock = self
            .file
            .unlock()
            .map_err(|error| format!("rollback anchor unlock failed: {error}"));
        match (result, unlock) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    fn write_next(
        &self,
        current_record_generation: u64,
        store_generation: u64,
        anchor_instance_id: &str,
    ) -> Result<(), String> {
        let record = self.prepare_next(
            current_record_generation,
            store_generation,
            anchor_instance_id,
        )?;
        self.commit_prepared(&record)
    }

    #[allow(
        clippy::indexing_slicing,
        reason = "Fixed slot layout bounds every constant offset; variable payload lengths are checked before slicing and record pairs require length two."
    )]
    fn prepare_next(
        &self,
        current_record_generation: u64,
        store_generation: u64,
        anchor_instance_id: &str,
    ) -> Result<GenerationRecord, String> {
        let record_generation = current_record_generation
            .checked_add(1)
            .ok_or_else(|| "rollback anchor record generation overflowed".to_string())?;
        let record = GenerationRecord {
            anchor_instance_id: anchor_instance_id.to_owned(),
            format: "chio.sqlite-rollback-generation.v1".to_string(),
            record_generation,
            scope_sha256: self.scope_sha256.clone(),
            store_generation,
        };
        self.validate_record(&record)?;
        let payload = canonical_json_bytes(&record)
            .map_err(|error| format!("rollback anchor encoding failed: {error}"))?;
        if payload.is_empty() || payload.len() > MAX_PAYLOAD_BYTES {
            return Err("rollback anchor record exceeds its fixed slot".to_string());
        }
        self.ensure_shape()?;
        let slot_index = usize::try_from((record_generation - 1) % 2)
            .map_err(|_| "rollback anchor slot overflowed".to_string())?;
        let offset = slot_index * SLOT_SIZE;

        write_all_at(&self.file, &[0_u8; COMMIT_MARKER.len()], offset)
            .map_err(|error| format!("rollback anchor marker clear failed: {error}"))?;
        self.file
            .sync_data()
            .map_err(|error| format!("rollback anchor marker sync failed: {error}"))?;

        let mut slot = [0_u8; SLOT_SIZE];
        let payload_len = u32::try_from(payload.len())
            .map_err(|_| "rollback anchor payload length overflowed".to_string())?;
        slot[LENGTH_OFFSET..CHECKSUM_OFFSET].copy_from_slice(&payload_len.to_be_bytes());
        slot[CHECKSUM_OFFSET..PAYLOAD_OFFSET].copy_from_slice(sha256_hex(&payload).as_bytes());
        slot[PAYLOAD_OFFSET..PAYLOAD_OFFSET + payload.len()].copy_from_slice(&payload);
        write_all_at(&self.file, &slot, offset)
            .map_err(|error| format!("rollback anchor slot write failed: {error}"))?;
        self.file
            .sync_data()
            .map_err(|error| format!("rollback anchor slot sync failed: {error}"))?;
        self.validate_identity()?;
        let mut persisted_slot = [0_u8; SLOT_SIZE];
        read_exact_at(&self.file, &mut persisted_slot, offset)
            .map_err(|error| format!("rollback anchor prepared read failed: {error}"))?;
        if persisted_slot[..COMMIT_MARKER.len()]
            .iter()
            .any(|byte| *byte != 0)
            || self.decode_slot(&persisted_slot)? != record
        {
            return Err("rollback anchor prepared write did not round trip".to_string());
        }
        Ok(record)
    }

    fn commit_prepared(&self, record: &GenerationRecord) -> Result<(), String> {
        let slot_index = usize::try_from((record.record_generation - 1) % 2)
            .map_err(|_| "rollback anchor slot overflowed".to_string())?;
        let offset = slot_index * SLOT_SIZE;
        write_all_at(&self.file, COMMIT_MARKER, offset)
            .map_err(|error| format!("rollback anchor commit failed: {error}"))?;
        self.file
            .sync_all()
            .map_err(|error| format!("rollback anchor commit sync failed: {error}"))?;
        self.validate_identity()?;

        let persisted = self
            .load_record()?
            .ok_or_else(|| "rollback anchor write was not durable".to_string())?;
        if persisted.corrupt_slot || persisted.interrupted_slot || persisted.record != *record {
            return Err("rollback anchor write did not round trip".to_string());
        }
        Ok(())
    }

    fn recover_prepared_for_store_generation(
        &self,
        loaded: LoadedRecord,
        store_generation: u64,
    ) -> Result<LoadedRecord, String> {
        if loaded.record.store_generation == store_generation {
            return Ok(loaded);
        }
        let Some(prepared) = loaded.prepared_record.as_ref() else {
            return Ok(loaded);
        };
        if loaded.record.record_generation.checked_add(1) != Some(prepared.record_generation)
            || loaded.record.store_generation.checked_add(1) != Some(prepared.store_generation)
            || prepared.scope_sha256 != loaded.record.scope_sha256
            || prepared.anchor_instance_id != loaded.record.anchor_instance_id
        {
            return Err(
                "prepared rollback anchor does not extend the committed history".to_string(),
            );
        }
        if prepared.store_generation != store_generation {
            return Ok(loaded);
        }
        self.commit_prepared(prepared)?;
        let recovered = self
            .load_record()?
            .ok_or_else(|| "recovered rollback generation is absent".to_string())?;
        if recovered.record.store_generation != store_generation
            || recovered.corrupt_slot
            || recovered.interrupted_slot
        {
            return Err("prepared rollback anchor recovery did not round trip".to_string());
        }
        Ok(recovered)
    }

    fn load_record(&self) -> Result<Option<LoadedRecord>, String> {
        match self.load_anchor_state()? {
            AnchorLoadState::Empty => Ok(None),
            AnchorLoadState::PreparedInitial(_) => {
                Err("rollback anchor has no committed slot".to_string())
            }
            AnchorLoadState::Committed(loaded) => Ok(Some(loaded)),
        }
    }

    #[allow(
        clippy::indexing_slicing,
        reason = "Fixed slot layout bounds every constant offset; variable payload lengths are checked before slicing and record pairs require length two."
    )]
    fn load_anchor_state(&self) -> Result<AnchorLoadState, String> {
        self.ensure_shape()?;
        let mut records = Vec::with_capacity(SLOT_COUNT);
        let mut corrupt_slot = false;
        let mut interrupted_slot = false;
        let mut prepared_record = None;
        for slot_index in 0..SLOT_COUNT {
            let mut slot = [0_u8; SLOT_SIZE];
            read_exact_at(&self.file, &mut slot, slot_index * SLOT_SIZE)
                .map_err(|error| format!("rollback anchor read failed: {error}"))?;
            let marker = &slot[..COMMIT_MARKER.len()];
            if marker.iter().all(|byte| *byte == 0) {
                if slot[COMMIT_MARKER.len()..].iter().any(|byte| *byte != 0) {
                    interrupted_slot = true;
                    if let Ok(record) = self.decode_slot(&slot) {
                        if prepared_record.replace(record).is_some() {
                            return Err(
                                "rollback anchor contains multiple prepared slots".to_string()
                            );
                        }
                    }
                }
                continue;
            }
            if marker != COMMIT_MARKER {
                interrupted_slot = true;
                match self.decode_slot(&slot) {
                    Ok(record) => {
                        if prepared_record.replace(record).is_some() {
                            return Err(
                                "rollback anchor contains multiple prepared slots".to_string()
                            );
                        }
                    }
                    Err(_) => corrupt_slot = true,
                }
                continue;
            }
            match self.decode_slot(&slot) {
                Ok(record) => records.push(record),
                Err(_) => corrupt_slot = true,
            }
        }
        records.sort_by_key(|record| record.record_generation);
        if records.len() == 2 {
            let prior = &records[0];
            let current = &records[1];
            if prior.record_generation.checked_add(1) != Some(current.record_generation)
                || current.scope_sha256 != prior.scope_sha256
                || current.anchor_instance_id != prior.anchor_instance_id
                || current.store_generation < prior.store_generation
            {
                return Err("rollback anchor slots do not form one monotonic history".to_string());
            }
        }
        let Some(record) = records.pop() else {
            if corrupt_slot {
                return Err("rollback anchor has no committed slot".to_string());
            }
            if let Some(prepared) = prepared_record {
                return Ok(AnchorLoadState::PreparedInitial(prepared));
            }
            if interrupted_slot {
                return Err("rollback anchor has no committed slot".to_string());
            }
            return Ok(AnchorLoadState::Empty);
        };
        Ok(AnchorLoadState::Committed(LoadedRecord {
            record,
            prepared_record,
            corrupt_slot,
            interrupted_slot,
        }))
    }

    #[allow(
        clippy::indexing_slicing,
        reason = "Fixed slot layout bounds every constant offset; variable payload lengths are checked before slicing and record pairs require length two."
    )]
    fn decode_slot(&self, slot: &[u8; SLOT_SIZE]) -> Result<GenerationRecord, String> {
        let payload_len = u32::from_be_bytes(
            slot[LENGTH_OFFSET..CHECKSUM_OFFSET]
                .try_into()
                .map_err(|_| "rollback anchor length is corrupt".to_string())?,
        );
        let payload_len = usize::try_from(payload_len)
            .map_err(|_| "rollback anchor length overflowed".to_string())?;
        if payload_len == 0 || payload_len > MAX_PAYLOAD_BYTES {
            return Err("rollback anchor length is invalid".to_string());
        }
        let payload_end = PAYLOAD_OFFSET + payload_len;
        if slot[payload_end..].iter().any(|byte| *byte != 0) {
            return Err("rollback anchor padding is corrupt".to_string());
        }
        let payload = &slot[PAYLOAD_OFFSET..payload_end];
        if slot[CHECKSUM_OFFSET..PAYLOAD_OFFSET] != sha256_hex(payload).as_bytes()[..] {
            return Err("rollback anchor checksum is invalid".to_string());
        }
        let record: GenerationRecord =
            chio_core::canonical::UntrustedJsonText::from_wire(payload, 64 * 1024 * 1024)
                .and_then(|input| input.decode_signed())
                .map_err(|error| format!("rollback anchor is invalid JSON: {error}"))?;
        if canonical_json_bytes(&record)
            .map_err(|error| format!("rollback anchor encoding failed: {error}"))?
            != payload
        {
            return Err("rollback anchor is not canonical JSON".to_string());
        }
        self.validate_record(&record)?;
        Ok(record)
    }

    fn validate_record(&self, record: &GenerationRecord) -> Result<(), String> {
        let anchor_instance_id = uuid::Uuid::parse_str(&record.anchor_instance_id)
            .map_err(|_| "rollback anchor instance id is invalid".to_string())?;
        if record.format != "chio.sqlite-rollback-generation.v1"
            || record.record_generation == 0
            || record.scope_sha256 != self.scope_sha256
            || anchor_instance_id.to_string() != record.anchor_instance_id
        {
            return Err("rollback anchor record is invalid".to_string());
        }
        Ok(())
    }

    fn ensure_shape(&self) -> Result<(), String> {
        let length = self
            .file
            .metadata()
            .map_err(|error| format!("rollback anchor metadata failed: {error}"))?
            .len();
        let expected =
            u64::try_from(FILE_SIZE).map_err(|_| "rollback anchor size overflowed".to_string())?;
        if length == 0 {
            self.file
                .set_len(expected)
                .map_err(|error| format!("rollback anchor sizing failed: {error}"))?;
            self.file
                .sync_all()
                .map_err(|error| format!("rollback anchor sizing sync failed: {error}"))?;
        } else if length != expected {
            return Err("rollback anchor has an invalid size".to_string());
        }
        Ok(())
    }

    fn validate_identity(&self) -> Result<(), String> {
        validate_secure_root(&self.root)?;
        let path_metadata = fs::symlink_metadata(&self.path)
            .map_err(|error| format!("rollback anchor path metadata failed: {error}"))?;
        let file_metadata = self
            .file
            .metadata()
            .map_err(|error| format!("rollback anchor file metadata failed: {error}"))?;
        for metadata in [&path_metadata, &file_metadata] {
            validate_anchor_metadata(metadata)?;
            if metadata_device(metadata)? != self.expected_device
                || metadata_inode(metadata)? != self.expected_inode
            {
                return Err("rollback anchor inode changed".to_string());
            }
        }
        Ok(())
    }
}

fn process_anchor_lock(path: &Path) -> Result<Arc<Mutex<()>>, String> {
    let locks = PROCESS_ANCHOR_LOCKS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut locks = locks
        .lock()
        .map_err(|_| "rollback anchor lock registry is poisoned".to_string())?;
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(path).and_then(Weak::upgrade) {
        return Ok(lock);
    }
    let lock = Arc::new(Mutex::new(()));
    locks.insert(path.to_path_buf(), Arc::downgrade(&lock));
    Ok(lock)
}

fn unix_only(_error: std::io::Error) -> String {
    "rollback generation anchors require Unix file identity".to_string()
}

fn validate_secure_root(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("rollback anchor root metadata failed: {error}"))?;
    if !custody::private_directory(&metadata).map_err(unix_only)? {
        return Err("rollback anchor root has unsafe ownership or permissions".to_string());
    }
    Ok(())
}

fn validate_anchor_metadata(metadata: &fs::Metadata) -> Result<(), String> {
    if !custody::private_file(metadata).map_err(unix_only)? {
        return Err("rollback anchor file has unsafe ownership or permissions".to_string());
    }
    Ok(())
}

fn metadata_device(metadata: &fs::Metadata) -> Result<u64, String> {
    custody::device_inode(metadata)
        .map(|(device, _)| device)
        .map_err(unix_only)
}

fn metadata_inode(metadata: &fs::Metadata) -> Result<u64, String> {
    custody::device_inode(metadata)
        .map(|(_, inode)| inode)
        .map_err(unix_only)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn secure_root(path: &Path) {
        assert!(fs::set_permissions(path, fs::Permissions::from_mode(0o700)).is_ok());
    }

    fn counter(generation: u64) -> StoreHead {
        StoreHead::counter_only(generation)
    }

    fn open_anchor(scope: &[u8]) -> (tempfile::TempDir, RollbackGenerationAnchor) {
        let Ok(root) = tempfile::tempdir() else {
            panic!("create anchor root");
        };
        secure_root(root.path());
        match RollbackGenerationAnchor::open(root.path(), scope) {
            Ok(anchor) => (root, anchor),
            Err(error) => panic!("open anchor: {error}"),
        }
    }

    #[test]
    fn independent_anchors_receive_distinct_global_instance_ids() {
        let Ok(first_root) = tempfile::tempdir() else {
            panic!("create first anchor root");
        };
        let Ok(second_root) = tempfile::tempdir() else {
            panic!("create second anchor root");
        };
        secure_root(first_root.path());
        secure_root(second_root.path());
        let first = match RollbackGenerationAnchor::open(first_root.path(), b"shared-scope") {
            Ok(anchor) => anchor,
            Err(error) => panic!("open first anchor: {error}"),
        };
        let second = match RollbackGenerationAnchor::open(second_root.path(), b"shared-scope") {
            Ok(anchor) => anchor,
            Err(error) => panic!("open second anchor: {error}"),
        };
        assert!(first.bind_initial_while(|| Ok((counter(0), true))).is_ok());
        assert!(second.bind_initial_while(|| Ok((counter(0), true))).is_ok());
        let Ok(first_id) = first.instance_id() else {
            panic!("load first anchor id");
        };
        let Ok(second_id) = second.instance_id() else {
            panic!("load second anchor id");
        };
        assert_ne!(first_id, second_id);
    }

    #[test]
    fn prepared_initial_generation_recovers_only_for_an_empty_store() {
        let Ok(root) = tempfile::tempdir() else {
            panic!("create anchor root");
        };
        secure_root(root.path());
        let anchor = match RollbackGenerationAnchor::open(root.path(), b"prepared-initial") {
            Ok(anchor) => anchor,
            Err(error) => panic!("open anchor: {error}"),
        };
        let instance_id = uuid::Uuid::now_v7().to_string();
        let Ok(prepared) = anchor.prepare_next(0, 0, &instance_id) else {
            panic!("prepare initial generation");
        };
        drop(anchor);

        let reopened = match RollbackGenerationAnchor::open(root.path(), b"prepared-initial") {
            Ok(anchor) => anchor,
            Err(error) => panic!("reopen anchor: {error}"),
        };
        assert!(reopened
            .bind_initial_while(|| Ok((counter(0), false)))
            .is_err());
        assert!(reopened
            .bind_initial_while(|| Ok((counter(1), false)))
            .is_err());
        assert!(reopened
            .bind_initial_while(|| Ok((counter(0), true)))
            .is_ok());
        assert_eq!(reopened.instance_id().as_deref(), Ok(instance_id.as_str()));
        let Ok(Some(loaded)) = reopened.load_record() else {
            panic!("load recovered initial generation");
        };
        assert_eq!(loaded.record, prepared);
        assert!(!loaded.corrupt_slot);
        assert!(!loaded.interrupted_slot);
    }

    #[test]
    fn marker_cleared_inactive_slot_recovers_from_surviving_generation() {
        let Ok(root) = tempfile::tempdir() else {
            panic!("create anchor root");
        };
        secure_root(root.path());
        let anchor = match RollbackGenerationAnchor::open(root.path(), b"interrupted-rewrite") {
            Ok(anchor) => anchor,
            Err(error) => panic!("open anchor: {error}"),
        };
        assert!(anchor.bind_initial_while(|| Ok((counter(0), true))).is_ok());
        let mut store_generation = 0;
        assert!(anchor
            .advance_while(&counter(0), &counter(1), || {
                store_generation = 1;
                Ok(())
            })
            .is_ok());

        assert!(write_all_at(&anchor.file, &[0_u8; COMMIT_MARKER.len()], 0).is_ok());
        assert!(anchor.file.sync_data().is_ok());
        assert!(anchor.verify(&counter(store_generation)).is_ok());
        assert!(anchor
            .advance_while(&counter(1), &counter(2), || {
                store_generation = 2;
                Ok(())
            })
            .is_ok());
        assert!(anchor.verify(&counter(store_generation)).is_ok());
    }

    #[test]
    fn prepared_generation_recovers_after_the_store_commit() {
        let Ok(root) = tempfile::tempdir() else {
            panic!("create anchor root");
        };
        secure_root(root.path());
        let anchor = match RollbackGenerationAnchor::open(root.path(), b"prepared-store-commit") {
            Ok(anchor) => anchor,
            Err(error) => panic!("open anchor: {error}"),
        };
        assert!(anchor.bind_initial_while(|| Ok((counter(0), true))).is_ok());
        let Ok(instance_id) = anchor.instance_id() else {
            panic!("load anchor instance id");
        };
        assert!(anchor.prepare_next(1, 1, &instance_id).is_ok());

        assert!(anchor.verify(&counter(1)).is_ok());
        let Ok(loaded) = anchor.load_record() else {
            panic!("load recovered anchor");
        };
        let Some(loaded) = loaded else {
            panic!("recovered anchor is absent");
        };
        assert_eq!(loaded.record.store_generation, 1);
        assert!(!loaded.interrupted_slot);
    }

    #[test]
    fn torn_commit_marker_recovers_after_the_store_commit() {
        let Ok(root) = tempfile::tempdir() else {
            panic!("create anchor root");
        };
        secure_root(root.path());
        let anchor = match RollbackGenerationAnchor::open(root.path(), b"torn-commit-marker") {
            Ok(anchor) => anchor,
            Err(error) => panic!("open anchor: {error}"),
        };
        assert!(anchor.bind_initial_while(|| Ok((counter(0), true))).is_ok());
        let Ok(instance_id) = anchor.instance_id() else {
            panic!("load anchor instance id");
        };
        let Ok(prepared) = anchor.prepare_next(1, 1, &instance_id) else {
            panic!("prepare next generation");
        };
        let slot_index = match usize::try_from((prepared.record_generation - 1) % 2) {
            Ok(index) => index,
            Err(_) => panic!("prepared slot index fits usize"),
        };
        let offset = slot_index * SLOT_SIZE;
        assert!(write_all_at(&anchor.file, &COMMIT_MARKER[..4], offset).is_ok());
        assert!(anchor.file.sync_data().is_ok());

        assert!(anchor.verify(&counter(1)).is_ok());
        let Ok(Some(loaded)) = anchor.load_record() else {
            panic!("load recovered torn-marker anchor");
        };
        assert_eq!(loaded.record, prepared);
        assert!(!loaded.corrupt_slot);
        assert!(!loaded.interrupted_slot);
        let mut committed_marker = [0_u8; COMMIT_MARKER.len()];
        assert!(read_exact_at(&anchor.file, &mut committed_marker, offset).is_ok());
        assert_eq!(&committed_marker, COMMIT_MARKER);
    }

    #[test]
    fn malformed_marker_without_a_valid_prepared_record_remains_corrupt() {
        let Ok(root) = tempfile::tempdir() else {
            panic!("create anchor root");
        };
        secure_root(root.path());
        let anchor = match RollbackGenerationAnchor::open(root.path(), b"corrupt-marker") {
            Ok(anchor) => anchor,
            Err(error) => panic!("open anchor: {error}"),
        };
        assert!(anchor.bind_initial_while(|| Ok((counter(0), true))).is_ok());
        assert!(write_all_at(&anchor.file, b"CORRUPT!", SLOT_SIZE).is_ok());
        assert!(anchor.file.sync_data().is_ok());

        assert_eq!(
            anchor.verify(&counter(0)),
            Err("rollback anchor contains a corrupt slot".to_string())
        );
    }

    #[test]
    fn failed_store_commit_leaves_the_prior_generation_usable() {
        let Ok(root) = tempfile::tempdir() else {
            panic!("create anchor root");
        };
        secure_root(root.path());
        let anchor = match RollbackGenerationAnchor::open(root.path(), b"failed-store-commit") {
            Ok(anchor) => anchor,
            Err(error) => panic!("open anchor: {error}"),
        };
        assert!(anchor.bind_initial_while(|| Ok((counter(0), true))).is_ok());
        assert!(anchor
            .advance_while(&counter(0), &counter(1), || Err(
                "injected SQLite commit failure".to_string()
            ))
            .is_err());
        assert!(anchor.verify(&counter(0)).is_ok());
        assert!(anchor
            .advance_while(&counter(0), &counter(1), || Ok(()))
            .is_ok());
        assert!(anchor.verify(&counter(1)).is_ok());
    }

    #[test]
    fn chained_anchor_refuses_an_equal_generation_fork() {
        let (_root, anchor) = open_anchor(b"chained-fork");
        let genesis = StoreHead::chained(0, "0".repeat(64));
        let live = StoreHead::chained(1, "a".repeat(64));
        let fork = StoreHead::chained(1, "f".repeat(64));
        assert!(anchor
            .bind_initial_while(|| Ok((genesis.clone(), true)))
            .is_ok());
        assert!(anchor.advance_while(&genesis, &live, || Ok(())).is_ok());
        assert!(anchor.verify(&live).is_ok());
        assert_eq!(
            anchor.verify(&fork),
            Err("store does not match its protected rollback generation".to_string())
        );
        assert!(anchor
            .advance_while(&fork, &StoreHead::chained(2, "b".repeat(64)), || Ok(()))
            .is_err());
        assert!(anchor.verify(&live).is_ok());
    }

    #[test]
    fn anchor_refuses_a_head_binding_change() {
        let (_root, anchor) = open_anchor(b"binding-change");
        assert!(anchor.bind_initial_while(|| Ok((counter(0), true))).is_ok());
        assert!(anchor
            .advance_while(&counter(0), &counter(1), || Ok(()))
            .is_ok());
        assert!(anchor
            .verify(&StoreHead::chained(1, "a".repeat(64)))
            .is_err());
        assert!(anchor
            .advance_while(&counter(1), &StoreHead::chained(2, "a".repeat(64)), || Ok(
                ()
            ))
            .is_err());
        assert!(anchor.verify(&counter(1)).is_ok());
    }

    #[test]
    fn slot_without_a_store_head_is_corrupt() {
        #[derive(Serialize)]
        struct UnboundRecord {
            anchor_instance_id: String,
            format: String,
            record_generation: u64,
            scope_sha256: String,
            store_generation: u64,
        }

        let (_root, anchor) = open_anchor(b"unbound-layout");
        assert!(anchor.bind_initial_while(|| Ok((counter(0), true))).is_ok());
        let Ok(instance_id) = anchor.instance_id() else {
            panic!("load anchor instance id");
        };
        let Ok(payload) = canonical_json_bytes(&UnboundRecord {
            anchor_instance_id: instance_id,
            format: "chio.sqlite-rollback-generation.v1".to_string(),
            record_generation: 2,
            scope_sha256: sha256_hex(b"unbound-layout"),
            store_generation: 1,
        }) else {
            panic!("encode unbound record");
        };
        let Ok(payload_len) = u32::try_from(payload.len()) else {
            panic!("payload length fits u32");
        };
        let mut slot = [0_u8; SLOT_SIZE];
        slot[..COMMIT_MARKER.len()].copy_from_slice(COMMIT_MARKER);
        slot[LENGTH_OFFSET..CHECKSUM_OFFSET].copy_from_slice(&payload_len.to_be_bytes());
        slot[CHECKSUM_OFFSET..PAYLOAD_OFFSET].copy_from_slice(sha256_hex(&payload).as_bytes());
        slot[PAYLOAD_OFFSET..PAYLOAD_OFFSET + payload.len()].copy_from_slice(&payload);
        assert!(write_all_at(&anchor.file, &slot, SLOT_SIZE).is_ok());
        assert!(anchor.file.sync_data().is_ok());

        assert_eq!(
            anchor.verify(&counter(1)),
            Err("rollback anchor contains a corrupt slot".to_string())
        );
    }
}
