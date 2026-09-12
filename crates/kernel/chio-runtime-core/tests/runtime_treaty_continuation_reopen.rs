//! Reopen coverage for the durable treaty continuation fence.
//!
//! A treaty continuation is consumed at admission and released only when the
//! owning admission is denied before dispatch. A runtime that stops between
//! those two points leaves the consumed marker behind in the store file.
//! Each case here reproduces that state by closing the store handle after
//! the consume and before any release, then reopening the same path: the
//! marker must keep denying replay by every admission, including the owner,
//! until the owner releases it, and a release by any other admission must
//! leave it in place.
//!
//! The close is graceful, so this exercises the reopen path rather than
//! SQLite's own recovery from a connection killed mid-transaction.

use chio_kernel::RuntimeAdmissionHook;
use chio_runtime_core::{
    ChioRuntimeAdmissionHook, RuntimeAdmissionProfile, RuntimeAdmissionStore,
    SqliteRuntimeOrchestrationStore, CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA,
};
use std::io;
use std::path::Path;

const CONTINUATION_ID: &str = "continue-treaty-1";
const OWNER_ADMISSION_ID: &str = "adm-treaty-1";
const FOREIGN_ADMISSION_ID: &str = "adm-treaty-2";
const REPLAY_CODE: &str = "chio_treaty_continuation_replay";

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Consume the continuation and close the store handle before any release,
/// which is the state a stop between admission and pre-dispatch denial
/// leaves behind. Asserts the store is file-backed, so a store that grew an
/// in-memory fallback would fail here instead of quietly turning every case
/// below into a single-handle test.
fn consume_then_close(path: &Path) -> TestResult {
    let store = SqliteRuntimeOrchestrationStore::open(path)?;
    store.consume_treaty_continuation(CONTINUATION_ID, OWNER_ADMISSION_ID)?;
    drop(store);
    assert!(
        path.is_file(),
        "runtime orchestration store is not file-backed at {}",
        path.display()
    );
    Ok(())
}

fn assert_replay_denied(store: &SqliteRuntimeOrchestrationStore, admission_id: &str) -> TestResult {
    match store.consume_treaty_continuation(CONTINUATION_ID, admission_id) {
        Ok(()) => Err(io::Error::other(format!(
            "treaty continuation {CONTINUATION_ID} was consumable again by {admission_id}"
        ))
        .into()),
        Err(error) => {
            assert_eq!(error.code(), REPLAY_CODE, "{error}");
            assert!(
                error.to_string().contains(CONTINUATION_ID),
                "replay rejection does not name the continuation: {error}"
            );
            Ok(())
        }
    }
}

fn reservation_metadata(admission_id: &str) -> serde_json::Value {
    serde_json::json!({
        "chio_runtime": {
            "admission_id": admission_id,
            "reserved_treaty_continuation_id": CONTINUATION_ID,
        }
    })
}

fn profile() -> RuntimeAdmissionProfile {
    RuntimeAdmissionProfile {
        schema: CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA.to_string(),
        profile_id: "profile-treaty-continuation".to_string(),
        local_kernel_id: "kernel.vendor-b".to_string(),
        verifier_id: "did:chio:buyer-verifier".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
    }
}

#[test]
fn consumed_treaty_continuation_survives_reopen_until_owner_release() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("runtime-treaty-continuation.sqlite3");
    consume_then_close(&path)?;

    let reopened = SqliteRuntimeOrchestrationStore::open(&path)?;
    assert_replay_denied(&reopened, OWNER_ADMISSION_ID)?;
    assert_replay_denied(&reopened, FOREIGN_ADMISSION_ID)?;
    reopened.release_treaty_continuation(CONTINUATION_ID, OWNER_ADMISSION_ID)?;
    drop(reopened);

    let released = SqliteRuntimeOrchestrationStore::open(&path)?;
    released.consume_treaty_continuation(CONTINUATION_ID, OWNER_ADMISSION_ID)?;
    drop(released);

    let reconsumed = SqliteRuntimeOrchestrationStore::open(&path)?;
    assert_replay_denied(&reconsumed, FOREIGN_ADMISSION_ID)
}

#[test]
fn foreign_admission_release_leaves_consumed_treaty_continuation_durable() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("runtime-treaty-continuation.sqlite3");
    consume_then_close(&path)?;

    let reopened = SqliteRuntimeOrchestrationStore::open(&path)?;
    reopened.release_treaty_continuation(CONTINUATION_ID, FOREIGN_ADMISSION_ID)?;
    drop(reopened);

    let after_foreign_release = SqliteRuntimeOrchestrationStore::open(&path)?;
    assert_replay_denied(&after_foreign_release, OWNER_ADMISSION_ID)?;
    assert_replay_denied(&after_foreign_release, FOREIGN_ADMISSION_ID)?;
    after_foreign_release.release_treaty_continuation(CONTINUATION_ID, OWNER_ADMISSION_ID)?;
    drop(after_foreign_release);

    let after_owner_release = SqliteRuntimeOrchestrationStore::open(&path)?;
    after_owner_release.consume_treaty_continuation(CONTINUATION_ID, FOREIGN_ADMISSION_ID)?;
    Ok(())
}

#[test]
fn runtime_hook_release_after_reopen_is_scoped_to_the_owning_admission() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("runtime-treaty-continuation.sqlite3");
    consume_then_close(&path)?;

    let hook =
        ChioRuntimeAdmissionHook::new(profile(), SqliteRuntimeOrchestrationStore::open(&path)?);
    let observer = SqliteRuntimeOrchestrationStore::open(&path)?;

    hook.release_reserved(&reservation_metadata(FOREIGN_ADMISSION_ID))?;
    assert_replay_denied(&observer, OWNER_ADMISSION_ID)?;
    assert_replay_denied(&observer, FOREIGN_ADMISSION_ID)?;

    hook.release_reserved(&reservation_metadata(OWNER_ADMISSION_ID))?;
    observer.consume_treaty_continuation(CONTINUATION_ID, OWNER_ADMISSION_ID)?;
    drop(hook);
    drop(observer);

    let reopened = SqliteRuntimeOrchestrationStore::open(&path)?;
    assert_replay_denied(&reopened, FOREIGN_ADMISSION_ID)
}
