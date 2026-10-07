//! Default-off byte observations for two exact native fixture requests.
use super::*;
use chio_security_types::knowledge::ArtifactReleaseKindV1;
use chio_security_types::recovery::RequestId;
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

const FIXTURE_REQUEST: &str = "bounded-envelope-restore";
const CHUNK_FIXTURE_REQUEST: &str = "chunked-checkpoint-lost-ack";

fn fixture_request(request: &RequestId) -> bool {
    matches!(request.as_str(), FIXTURE_REQUEST | CHUNK_FIXTURE_REQUEST)
}
const MAX_OBSERVERS: usize = 16;
type FixtureKey = (String, String, String, String);
type EncodingCounts = (usize, usize);
type Observers = BTreeMap<FixtureKey, EncodingObservation>;

#[derive(Clone, Copy, Default)]
struct EncodingObservation {
    journal: Option<EncodingCounts>,
    restore: Option<usize>,
}

static OBSERVERS: OnceLock<Mutex<Observers>> = OnceLock::new();

fn key(scope: &RecoveryScopeV1, request: &RequestId) -> FixtureKey {
    (
        scope.authority_domain.as_str().to_owned(),
        scope.tenant_id.as_str().to_owned(),
        scope.process_id.as_str().to_owned(),
        request.as_str().to_owned(),
    )
}

struct ObserverGuard {
    key: FixtureKey,
}

impl Drop for ObserverGuard {
    fn drop(&mut self) {
        if let Some(observers) = OBSERVERS.get() {
            if let Ok(mut observers) = observers.lock() {
                observers.remove(&self.key);
            }
        }
    }
}

impl SqliteAdmissionOperationStore {
    /// This guard observes two byte counts only. It changes no decision,
    /// protected row, native authority, output, label or storage ceiling.
    pub fn observe_knowledge_join_encoding_fixture(
        &self,
        scope: &RecoveryScopeV1,
        request: &RequestId,
    ) -> Result<impl Drop, AdmissionOperationStoreError> {
        if scope.authority_domain.as_str() != self.serving_owner.fence.store_uuid
            || !fixture_request(request)
        {
            return Err(invalid("knowledge encoding fixture binding"));
        }
        let key = key(scope, request);
        let mut observers = OBSERVERS
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .map_err(|_| invalid("knowledge encoding fixture poisoned"))?;
        if observers.len() >= MAX_OBSERVERS || observers.contains_key(&key) {
            return Err(invalid("knowledge encoding fixture already occupied"));
        }
        observers.insert(key.clone(), EncodingObservation::default());
        Ok(ObserverGuard { key })
    }

    /// The first number is the actual encoded journal payload; the second is
    /// the sum of retained before/after row-image bytes. No payload is returned.
    pub fn knowledge_join_encoding_fixture(
        &self,
        scope: &RecoveryScopeV1,
        request: &RequestId,
    ) -> Result<Option<(usize, usize)>, AdmissionOperationStoreError> {
        if scope.authority_domain.as_str() != self.serving_owner.fence.store_uuid
            || !fixture_request(request)
        {
            return Err(invalid("knowledge encoding fixture binding"));
        }
        let observers = OBSERVERS
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .map_err(|_| invalid("knowledge encoding fixture poisoned"))?;
        Ok(observers
            .get(&key(scope, request))
            .and_then(|counts| counts.journal))
    }

    /// A later phase may observe its internally constructed restore payload.
    /// This shares the same exact request guard and returns only its byte count.
    pub fn restore_record_encoding_fixture(
        &self,
        scope: &RecoveryScopeV1,
        request: &RequestId,
    ) -> Result<Option<usize>, AdmissionOperationStoreError> {
        if scope.authority_domain.as_str() != self.serving_owner.fence.store_uuid
            || !fixture_request(request)
        {
            return Err(invalid("knowledge encoding fixture binding"));
        }
        let observers = OBSERVERS
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .map_err(|_| invalid("knowledge encoding fixture poisoned"))?;
        Ok(observers
            .get(&key(scope, request))
            .and_then(|counts| counts.restore))
    }
}

pub(super) fn observe_wire(record: &Record, encoded_body: &[u8]) {
    let ArtifactReleaseKindV1::IndependentlyAdmitted { request } = &record.release.kind else {
        return;
    };
    if !fixture_request(request) {
        return;
    }
    let Some(observers) = OBSERVERS.get() else {
        return;
    };
    let fixture = key(&record.scope, request);
    if !observers
        .lock()
        .ok()
        .is_some_and(|observers| observers.contains_key(&fixture))
    {
        return;
    }
    let changes = record
        .changes
        .as_slice()
        .iter()
        .try_fold(0_usize, |sum, change| {
            sum.checked_add(change.before.as_ref().map_or(0, String::len))
                .and_then(|sum| sum.checked_add(change.after.as_ref().map_or(0, String::len)))
        });
    let Some(changes) = changes else {
        return;
    };
    // Observation failures cannot influence the native decision or storage.
    if let Ok(mut observers) = observers.lock() {
        if let Some(slot) = observers.get_mut(&fixture) {
            slot.journal = Some((encoded_body.len(), changes));
        }
    }
}

pub(in crate::admission_operation_store) fn observe_restore_record_encoding_bytes_fixture(
    scope: &RecoveryScopeV1,
    request: &RequestId,
    encoded_body: &[u8],
) {
    if !fixture_request(request) {
        return;
    }
    let Some(observers) = OBSERVERS.get() else {
        return;
    };
    let fixture = key(scope, request);
    if !observers
        .lock()
        .ok()
        .is_some_and(|observers| observers.contains_key(&fixture))
    {
        return;
    }
    if let Ok(mut observers) = observers.lock() {
        if let Some(slot) = observers.get_mut(&fixture) {
            slot.restore = Some(encoded_body.len());
        }
    }
}
