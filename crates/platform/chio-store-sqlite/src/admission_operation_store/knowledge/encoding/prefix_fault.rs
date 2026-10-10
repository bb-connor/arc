//! A default-off real protected fault is bound to one actual Restore ACK.
use super::chunks::ChunkedBody;
use crate::admission_operation_store::knowledge::AuthenticatedCheckpointRestoreEncodingSource;
use crate::admission_operation_store::recovery::storage as protected;
use crate::admission_operation_store::{
    invariant, AdmissionOperationStoreError, SqliteAdmissionOperationStore,
};
use crate::serving_owner::SqliteServingOwner;
use chio_security_types::recovery::{RecoveryScopeV1, RequestId};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

const REQUEST: &str = "chunked-checkpoint-prefix-refusal";
const MAX_FIXTURES: usize = 16;
type FixtureKey = (String, String, String, String);
type Observation = (u64, u64, u32);

struct Fixture {
    owner: Arc<SqliteServingOwner>,
    observation: Option<Observation>,
}
static FIXTURES: OnceLock<Mutex<BTreeMap<FixtureKey, Fixture>>> = OnceLock::new();

fn key(scope: &RecoveryScopeV1, request: &RequestId) -> FixtureKey {
    (
        scope.authority_domain.as_str().to_owned(),
        scope.tenant_id.as_str().to_owned(),
        scope.process_id.as_str().to_owned(),
        request.as_str().to_owned(),
    )
}

pub struct KnowledgeRestorePrefixFaultGuard {
    key: FixtureKey,
}
impl Drop for KnowledgeRestorePrefixFaultGuard {
    fn drop(&mut self) {
        if let Some(fixtures) = FIXTURES.get() {
            if let Ok(mut fixtures) = fixtures.lock() {
                fixtures.remove(&self.key);
            }
        }
    }
}

impl SqliteAdmissionOperationStore {
    /// This explicitly requested test fault is available only through the
    /// admission-test-support feature. It owns the real Store serving authority
    /// and permits one private source-verified Uncertain ACK extra-ordinal append.
    pub fn inject_checkpoint_restore_extra_prefix_fixture(
        &self,
        scope: &RecoveryScopeV1,
        request: &RequestId,
    ) -> Result<KnowledgeRestorePrefixFaultGuard, AdmissionOperationStoreError> {
        if scope.authority_domain.as_str() != self.serving_owner.fence.store_uuid
            || request.as_str() != REQUEST
        {
            return Err(invalid("checkpoint prefix fault binding"));
        }
        let key = key(scope, request);
        let mut fixtures = FIXTURES
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .map_err(|_| invalid("checkpoint prefix fault poisoned"))?;
        if fixtures.len() >= MAX_FIXTURES || fixtures.contains_key(&key) {
            return Err(invalid("checkpoint prefix fault already occupied"));
        }
        fixtures.insert(
            key.clone(),
            Fixture {
                owner: self.serving_owner.clone(),
                observation: None,
            },
        );
        Ok(KnowledgeRestorePrefixFaultGuard { key })
    }
    /// Only actual append count and exact private body byte/chunk counts leave
    /// the guard. Bodies, labels, actor credentials and protected sources do not.
    pub fn checkpoint_restore_extra_prefix_fixture(
        &self,
        scope: &RecoveryScopeV1,
        request: &RequestId,
    ) -> Result<Option<Observation>, AdmissionOperationStoreError> {
        if scope.authority_domain.as_str() != self.serving_owner.fence.store_uuid
            || request.as_str() != REQUEST
        {
            return Err(invalid("checkpoint prefix fault observation binding"));
        }
        let fixtures = FIXTURES
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .map_err(|_| invalid("checkpoint prefix fault poisoned"))?;
        Ok(fixtures
            .get(&key(scope, request))
            .and_then(|fixture| fixture.observation))
    }
}

/// The call site is after actual source/body validation and before the native
/// plan captures its global head. No caller key, alternate owner or bytes enter.
pub(super) fn retain_extra_prefix_fixture(
    source: &AuthenticatedCheckpointRestoreEncodingSource<'_, '_>,
    body: &ChunkedBody,
) -> Result<(), AdmissionOperationStoreError> {
    let Some((scope, request)) = source.extra_prefix_fixture_binding() else {
        return Ok(());
    };
    if request.as_str() != REQUEST {
        return Ok(());
    }
    let Some(fixtures) = FIXTURES.get() else {
        return Ok(());
    };
    let mut fixtures = fixtures
        .lock()
        .map_err(|_| invalid("checkpoint prefix fault poisoned"))?;
    let Some(fixture) = fixtures.get_mut(&key(scope, request)) else {
        return Ok(());
    };
    if fixture.observation.is_some() {
        return Ok(());
    }
    let tx = source.transaction();
    let before: i64 = tx
        .query_row(
            "SELECT head_sequence FROM authority_global_commit_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| invalid("checkpoint prefix fault head"))?;
    let extra = protected::retain_restore_extra_ordinal_fixture(tx, &fixture.owner, source, body)?;
    let after: i64 = tx
        .query_row(
            "SELECT head_sequence FROM authority_global_commit_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| invalid("checkpoint prefix fault head"))?;
    if before.checked_add(1) != Some(after)
        || extra.global_commit_sequence()
            != u64::try_from(after).map_err(|_| invalid("checkpoint prefix fault ordinal"))?
        || extra.version() != 1
    {
        return Err(invalid(
            "checkpoint prefix fault did not append exactly one actual source",
        ));
    }
    let (bytes, count) = body.fixture_body_counts();
    fixture.observation = Some((1, bytes, count));
    Ok(())
}

fn invalid(reason: &str) -> AdmissionOperationStoreError {
    invariant(reason)
}
