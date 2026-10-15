//! Stored text whose SQLite `length` stops at an embedded NUL is refused by
//! the bounded SELECT itself. Each refusal differs from the message the Rust
//! check of the same field would give, so a selected oversized value would
//! fail these assertions.

use super::super::{verify_global_coverage, verify_local_history};
use super::super::{NativeIdentity, RecordKind};
use super::fixture::{assert_refused, EventSeed, Ledger, TestResult, SCOPE};

const OVERSIZED_TAIL_BYTES: usize = 1_048_576;

/// `prefix` then a NUL then a megabyte: SQLite `length` reports only `prefix`.
fn nul_text(prefix: &str) -> String {
    format!("{prefix}\0{}", "a".repeat(OVERSIZED_TAIL_BYTES))
}

#[test]
fn oversized_stored_key_refuses_in_local_key_enumeration() -> TestResult {
    let mut ledger = Ledger::new()?;
    ledger.publish("deployment:a", RecordKind::Deployment, b"{}", None)?;
    let key = nul_text("deployment:b");
    ledger.set_checks(false)?;
    ledger.write_record(SCOPE, &key, RecordKind::Deployment, b"{}", None)?;
    ledger.set_checks(true)?;
    assert!(ledger.checks_enforced()?);
    assert_refused(
        verify_local_history(&ledger.connection),
        "recovery record stored key exceeds its bound",
    );
    Ok(())
}

#[test]
fn oversized_scope_refuses_in_the_present_row_select() -> TestResult {
    let ledger = Ledger::new()?;
    let scope = nul_text(SCOPE);
    ledger.set_checks(false)?;
    ledger.write_record(&scope, "deployment:a", RecordKind::Deployment, b"{}", None)?;
    ledger.set_checks(true)?;
    assert!(ledger.checks_enforced()?);
    assert_refused(
        verify_local_history(&ledger.connection),
        "recovery record exceeds its bound",
    );
    Ok(())
}

#[test]
fn oversized_native_namespace_refuses_in_the_present_row_select() -> TestResult {
    let ledger = Ledger::new()?;
    let native = NativeIdentity {
        namespace: nul_text(&"cd".repeat(32)),
        request: "request-1".to_owned(),
    };
    ledger.set_checks(false)?;
    ledger.write_record(
        SCOPE,
        "workflow:w",
        RecordKind::Workflow,
        b"{}",
        Some(&native),
    )?;
    ledger.set_checks(true)?;
    assert!(ledger.checks_enforced()?);
    assert_refused(
        verify_local_history(&ledger.connection),
        "recovery record exceeds its bound",
    );
    Ok(())
}

#[test]
fn oversized_native_request_refuses_in_the_present_row_select() -> TestResult {
    let ledger = Ledger::new()?;
    let native = NativeIdentity {
        namespace: "cd".repeat(32),
        request: nul_text("r"),
    };
    ledger.set_checks(false)?;
    ledger.write_record(
        SCOPE,
        "workflow:w",
        RecordKind::Workflow,
        b"{}",
        Some(&native),
    )?;
    ledger.set_checks(true)?;
    assert!(ledger.checks_enforced()?);
    assert_refused(
        verify_local_history(&ledger.connection),
        "recovery record exceeds its bound",
    );
    Ok(())
}

#[test]
fn oversized_event_digest_refuses_in_the_event_select() -> TestResult {
    let mut ledger = Ledger::new()?;
    ledger.publish("deployment:a", RecordKind::Deployment, br#"{"v":1}"#, None)?;
    ledger.write_record(
        SCOPE,
        "deployment:a",
        RecordKind::Deployment,
        br#"{"v":2}"#,
        None,
    )?;
    let record_digest = nul_text(&"f".repeat(64));
    let head = ledger.head().to_owned();
    ledger.set_checks(false)?;
    ledger.append_event(&EventSeed {
        sequence: 2,
        key: "deployment:a",
        version: 2,
        record_digest: &record_digest,
        previous: &head,
        observed: 2,
    })?;
    ledger.set_checks(true)?;
    assert!(ledger.checks_enforced()?);
    assert_refused(
        verify_local_history(&ledger.connection),
        "recovery history event exceeds its bound",
    );
    Ok(())
}

#[test]
fn oversized_event_key_refuses_in_the_chain_select() -> TestResult {
    let mut ledger = Ledger::new()?;
    let first = ledger.publish("deployment:a", RecordKind::Deployment, b"{}", None)?;
    let key = nul_text("deployment:a");
    ledger.set_checks(false)?;
    ledger.append_event(&EventSeed {
        sequence: 2,
        key: &key,
        version: 1,
        record_digest: &"e".repeat(64),
        previous: &first.event_digest,
        observed: 2,
    })?;
    ledger.set_checks(true)?;
    assert!(ledger.checks_enforced()?);
    assert_refused(
        verify_local_history(&ledger.connection),
        "recovery history event exceeds its bound",
    );
    Ok(())
}

#[test]
fn oversized_global_reference_refuses_in_the_commit_select() -> TestResult {
    let mut ledger = Ledger::new()?;
    let first = ledger.publish("deployment:a", RecordKind::Deployment, b"{}", None)?;
    ledger.install_global_commits()?;
    ledger.commit(1, "deployment:a", 1, &nul_text(&first.event_digest))?;
    verify_local_history(&ledger.connection)?;
    assert_refused(
        verify_global_coverage(&ledger.connection),
        "recovery global commit reference exceeds its bound",
    );
    Ok(())
}

#[test]
fn maximum_multibyte_key_and_request_verify() -> TestResult {
    let mut ledger = Ledger::new()?;
    let key = "\u{1F642}".repeat(512);
    let native = NativeIdentity {
        namespace: "cd".repeat(32),
        request: "\u{1F642}".repeat(256),
    };
    assert_eq!((key.len(), native.request.len()), (2048, 1024));
    ledger.publish(&key, RecordKind::Workflow, b"{}", Some(&native))?;
    verify_local_history(&ledger.connection)?;
    Ok(())
}

#[test]
fn nul_record_keys_refuse_during_local_verification() -> TestResult {
    let ledger = Ledger::new()?;
    let key = "deployment:a\0hidden";
    ledger.set_checks(false)?;
    ledger.write_record(SCOPE, key, RecordKind::Deployment, b"{}", None)?;
    ledger.set_checks(true)?;
    assert!(ledger.checks_enforced()?);
    assert_refused(
        verify_local_history(&ledger.connection),
        "recovery record stored key exceeds its bound",
    );
    Ok(())
}

#[test]
fn nul_native_requests_refuse_before_the_value_is_selected() -> TestResult {
    let ledger = Ledger::new()?;
    let native = NativeIdentity {
        namespace: "cd".repeat(32),
        request: "request\0hidden".to_owned(),
    };
    ledger.set_checks(false)?;
    ledger.write_record(
        SCOPE,
        "workflow:w",
        RecordKind::Workflow,
        b"{}",
        Some(&native),
    )?;
    ledger.set_checks(true)?;
    assert!(ledger.checks_enforced()?);
    assert_refused(
        verify_local_history(&ledger.connection),
        "recovery record exceeds its bound",
    );
    Ok(())
}
