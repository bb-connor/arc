use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use chio_decoy::{
    PrivateDecoyRegistry, PrivilegedExportCredential, RegistryError, RegistryExportAuthorizer,
    RegistryExportGrant, RegistryKey, RegistryKeyProvider,
};
use chio_security_types::ports::{
    BoundedVec, Digest32, PortError, PortResult, SealedDecoyRegistryStore, TenantId,
};
use chio_security_types::{
    DecoyArtifactLookup, DecoyScan, SealedDecoyCasRequest, SealedDecoyPage, SealedDecoyRecord,
    SealedMarkerLookup, SealedPublicRefLookup,
};
use chio_test_support::prelude::*;

#[derive(Default)]
pub struct MemoryStore {
    rows: Mutex<BTreeMap<(TenantId, Digest32), SealedDecoyRecord>>,
    operations: Mutex<BTreeMap<(TenantId, Digest32), Digest32>>,
    transitions: Mutex<BTreeMap<(TenantId, Digest32), (Digest32, SealedDecoyRecord)>>,
    pub fail_reads: AtomicBool,
}

impl SealedDecoyRegistryStore for MemoryStore {
    fn load_by_id(&self, id: &DecoyArtifactLookup) -> PortResult<Option<SealedDecoyRecord>> {
        if self.fail_reads.load(Ordering::SeqCst) {
            return Err(PortError::unavailable());
        }
        Ok(self
            .rows
            .lock()
            .map_err(|_| PortError::unavailable())?
            .get(&(id.tenant_id.clone(), id.artifact_token))
            .cloned())
    }

    fn load_by_marker(&self, lookup: &SealedMarkerLookup) -> PortResult<Option<SealedDecoyRecord>> {
        if self.fail_reads.load(Ordering::SeqCst) {
            return Err(PortError::unavailable());
        }
        let rows = self.rows.lock().map_err(|_| PortError::unavailable())?;
        Ok(rows
            .values()
            .find(|row| {
                row.tenant_id == lookup.tenant_id
                    && row.surface == lookup.surface
                    && row.marker_token == lookup.marker_token
            })
            .cloned())
    }

    fn load_by_public_ref(
        &self,
        lookup: &SealedPublicRefLookup,
    ) -> PortResult<Option<SealedDecoyRecord>> {
        if self.fail_reads.load(Ordering::SeqCst) {
            return Err(PortError::unavailable());
        }
        let rows = self.rows.lock().map_err(|_| PortError::unavailable())?;
        Ok(rows
            .values()
            .find(|row| {
                row.tenant_id == lookup.tenant_id
                    && row.public_ref_token == Some(lookup.public_ref_token)
            })
            .cloned())
    }

    fn compare_and_swap(&self, request: &SealedDecoyCasRequest) -> PortResult<SealedDecoyRecord> {
        let mut operations = self
            .operations
            .lock()
            .map_err(|_| PortError::unavailable())?;
        let mut transitions = self
            .transitions
            .lock()
            .map_err(|_| PortError::unavailable())?;
        let mut rows = self.rows.lock().map_err(|_| PortError::unavailable())?;
        let operation_key = (request.record.tenant_id.clone(), request.operation_token);
        if let Some(artifact_token) = operations.get(&operation_key) {
            if *artifact_token != request.record.artifact_token {
                return Err(PortError::conflict());
            }
        }
        let transition_key = (request.record.tenant_id.clone(), request.transition_token);
        if let Some((artifact_token, result)) = transitions.get(&transition_key) {
            if *artifact_token == request.record.artifact_token && *result == request.record {
                return Ok(result.clone());
            }
            return Err(PortError::conflict());
        }
        let key = (
            request.record.tenant_id.clone(),
            request.record.artifact_token,
        );
        match (rows.get(&key), request.expected_generation) {
            (None, None) if request.record.generation == 0 => {}
            (Some(current), Some(expected))
                if current.generation == expected
                    && request.record.generation
                        == expected
                            .checked_add(1)
                            .ok_or_else(PortError::integrity_failure)?
                    && current.surface == request.record.surface
                    && current.public_ref_token == request.record.public_ref_token
                    && current.marker_token == request.record.marker_token
                    && current.version_hash == request.record.version_hash => {}
            _ => return Err(PortError::conflict()),
        }
        if rows.values().any(|current| {
            current.tenant_id == request.record.tenant_id
                && current.surface == request.record.surface
                && current.marker_token == request.record.marker_token
                && current.artifact_token != request.record.artifact_token
        }) {
            return Err(PortError::conflict());
        }
        if request.record.public_ref_token.is_some()
            && rows.values().any(|current| {
                current.tenant_id == request.record.tenant_id
                    && current.public_ref_token == request.record.public_ref_token
                    && current.artifact_token != request.record.artifact_token
            })
        {
            return Err(PortError::conflict());
        }
        rows.insert(key, request.record.clone());
        operations.insert(operation_key, request.record.artifact_token);
        transitions.insert(
            transition_key,
            (request.record.artifact_token, request.record.clone()),
        );
        Ok(request.record.clone())
    }

    fn scan(&self, scan: &DecoyScan) -> PortResult<SealedDecoyPage> {
        scan.validate().map_err(|_| PortError::invalid_data())?;
        let rows = self.rows.lock().map_err(|_| PortError::unavailable())?;
        let mut matching: Vec<_> = rows
            .values()
            .filter(|row| {
                row.tenant_id == scan.tenant_id
                    && scan
                        .after_artifact_token
                        .is_none_or(|cursor| row.artifact_token > cursor)
            })
            .cloned()
            .collect();
        matching.sort_by_key(|row| row.artifact_token);
        let has_more = matching.len() > usize::from(scan.limit);
        matching.truncate(usize::from(scan.limit));
        let next_artifact_token = has_more
            .then(|| matching.last().map(|row| row.artifact_token))
            .flatten();
        Ok(SealedDecoyPage {
            records: BoundedVec::new(matching).map_err(|_| PortError::integrity_failure())?,
            next_artifact_token,
        })
    }
}

struct Keys;

impl RegistryKeyProvider for Keys {
    fn key_for(&self, tenant_id: &TenantId) -> Result<RegistryKey, RegistryError> {
        let fill = match tenant_id.as_str() {
            "tenant-a" => 0xA1,
            "tenant-b" => 0xB2,
            _ => return Err(RegistryError::KeyUnavailable),
        };
        Ok(RegistryKey::from_bytes([fill; 64]))
    }
}

struct Exports;

impl RegistryExportAuthorizer for Exports {
    fn authorize(
        &self,
        _: &PrivilegedExportCredential,
        now_unix_ms: u64,
    ) -> Result<RegistryExportGrant, RegistryError> {
        RegistryExportGrant::new(
            TenantId::new("tenant-a").test_expect("valid tenant"),
            16,
            now_unix_ms + 1_000,
        )
    }
}

pub fn registry(store: Arc<MemoryStore>) -> PrivateDecoyRegistry {
    PrivateDecoyRegistry::new(store, Arc::new(Keys), Arc::new(Exports))
}
