use std::cell::Cell;

use chio_security_types::ports::{
    Digest32, EgressFenceRequest, FlowJoinRequest, FlowStateKey, FlowStateStore, IsolationEpochId,
    LineageId, RecordId, RequestId, SessionId, TenantId,
};
use chio_security_types::{InformationLabel, PrincipalId};
use rusqlite::Connection;

use super::{
    schema, Error, SecurityParticipantSourceBinding, SecurityParticipantSourceSnapshot,
    SqliteSecurityParticipantSource,
};
use crate::SqliteSecurityStateStore;

mod barriers;
mod codec;
mod crash;
mod declassification;
mod egress_history;
mod opening;
mod row_codec;

pub(crate) use declassification::{
    consumption as declassification_consumption_fixture,
    release as declassification_outcome_fixture,
};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

thread_local! { static FAIL_AFTER: Cell<u8> = const { Cell::new(0) }; }

pub(super) fn cutpoint(stage: u8) -> super::Result<()> {
    if FAIL_AFTER.get() == stage {
        return Err(Error::Invalid("injected source retirement cutpoint"));
    }
    if std::env::var("CHIO_SECURITY_SOURCE_CRASH_STAGE")
        .ok()
        .as_deref()
        == Some(stage.to_string().as_str())
    {
        std::process::abort();
    }
    Ok(())
}

struct ResetCutpoint;
impl Drop for ResetCutpoint {
    fn drop(&mut self) {
        FAIL_AFTER.set(0);
    }
}

fn binding() -> super::Result<SecurityParticipantSourceBinding> {
    SecurityParticipantSourceBinding::new(
        "private-source",
        "security-authority",
        "destination-store",
    )
}

fn key() -> TestResult<FlowStateKey> {
    Ok(FlowStateKey {
        tenant_id: TenantId::new("tenant")?,
        principal_id: PrincipalId::new("principal")?,
        lineage_id: LineageId::new("lineage")?,
        session_id: SessionId::new("session")?,
        isolation_epoch_id: IsolationEpochId::new("epoch")?,
    })
}

fn join_request(transition: &str) -> TestResult<FlowJoinRequest> {
    Ok(FlowJoinRequest {
        key: key()?,
        principal_join: InformationLabel::bottom(),
        lineage_join: InformationLabel::bottom(),
        session_join: InformationLabel::bottom(),
        transition_id: RecordId::new(transition)?,
    })
}

fn seed(path: &std::path::Path) -> TestResult<SqliteSecurityStateStore> {
    let store =
        SqliteSecurityStateStore::open_with_trusted_clock(path, std::sync::Arc::new(HistoryClock))?;
    let snapshot = store.join(&join_request("initial-join")?)?;
    store.acquire_egress_fence(&EgressFenceRequest {
        key: key()?,
        request_id: RequestId::new("request")?,
        request_hash: Digest32::new([1; 32]),
        expected_context_generation: snapshot.context_generation,
        expires_at_unix_ms: i64::MAX as u64,
    })?;
    Ok(store)
}

struct HistoryClock;

impl crate::security_state::SecurityStateClock for HistoryClock {
    fn now_unix_ms(&self) -> chio_security_types::ports::PortResult<u64> {
        Ok(1_000)
    }
}

/// Shared real history for source-retirement and destination-import tests.
pub(crate) fn seeded_security_history(
    path: &std::path::Path,
) -> TestResult<SqliteSecurityStateStore> {
    let store = seed(path)?;
    declassification::seed_history(&store)?;
    Ok(store)
}

#[test]
fn seals_exact_populated_flow_inventory_and_disables_existing_typed_handles() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("security.db");
    let store = seed(&path)?;
    let source = SqliteSecurityParticipantSource::open(&path)?;
    let expected = source.preview(&binding()?)?;
    assert_eq!(source.preview(&binding()?)?, expected);
    assert!(source.load_seal()?.is_none());
    assert!(store.load(&key()?)?.is_some());
    assert_eq!(
        SecurityParticipantSourceSnapshot::from_canonical_bytes(&expected.canonical_bytes()?)?,
        expected
    );
    assert_eq!(source.seal_exact(&expected)?.snapshot(), &expected);
    assert_eq!(source.seal_exact(&expected)?.snapshot(), &expected);
    assert!(source.preview(&binding()?).is_err());
    assert!(store.load(&key()?).is_err());
    assert!(store.join(&join_request("initial-join")?).is_err());
    assert!(store.join(&join_request("after-seal")?).is_err());
    assert!(SqliteSecurityStateStore::open(&path).is_err());
    drop(source);
    let reopened = SqliteSecurityParticipantSource::open(&path)?;
    reopened.verify_seal(&expected)?;
    assert!(!format!("{:?}", reopened.load_seal()?).contains("private-source"));
    Ok(())
}

#[test]
fn stale_source_expectation_fails_before_first_ddl_and_preserves_writers() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("security.db");
    let store = seed(&path)?;
    let source = SqliteSecurityParticipantSource::open(&path)?;
    let expected = source.preview(&binding()?)?;
    store.join(&join_request("concurrent-join")?)?;
    assert!(source.seal_exact(&expected).is_err());
    assert!(!schema::has_evidence(&Connection::open(&path)?)?);
    assert_ne!(source.preview(&binding()?)?, expected);
    store.join(&join_request("still-writable")?)?;
    Ok(())
}

#[test]
fn seal_errors_roll_back_every_precommit_cutpoint_and_recover_lost_ack() -> TestResult {
    let _reset = ResetCutpoint;
    for stage in 1..=5 {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("security.db");
        let store = seed(&path)?;
        let source = SqliteSecurityParticipantSource::open(&path)?;
        let expected = source.preview(&binding()?)?;
        FAIL_AFTER.set(stage);
        assert!(source.seal_exact(&expected).is_err());
        FAIL_AFTER.set(0);
        let sealed = source.load_seal()?;
        assert_eq!(sealed.is_some(), stage == 5);
        if stage < 5 {
            assert_eq!(source.preview(&binding()?)?, expected);
            assert!(store.load(&key()?)?.is_some());
        } else {
            source.verify_seal(&expected)?;
            assert!(store.load(&key()?).is_err());
        }
        assert_eq!(source.seal_exact(&expected)?.snapshot(), &expected);
    }
    Ok(())
}

#[test]
fn racing_new_join_and_seal_cannot_both_commit_against_the_old_inventory() -> TestResult {
    for _ in 0..8 {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("security.db");
        let store = seed(&path)?;
        let source = SqliteSecurityParticipantSource::open(&path)?;
        let expected = source.preview(&binding()?)?;
        let join = join_request("racing-new-join")?;
        let barrier = std::sync::Barrier::new(2);
        let (joined, sealed) = std::thread::scope(|scope| {
            let writer = scope.spawn(|| {
                barrier.wait();
                store.join(&join).is_ok()
            });
            barrier.wait();
            let sealed = source.seal_exact(&expected).is_ok();
            (writer.join(), sealed)
        });
        let joined = joined.map_err(|_| "source writer thread panicked")?;
        assert_ne!(
            joined, sealed,
            "exactly one competing transaction must commit"
        );
        if sealed {
            source.verify_seal(&expected)?;
        } else {
            assert!(source.load_seal()?.is_none());
            assert_ne!(source.preview(&binding()?)?, expected);
        }
    }
    Ok(())
}
