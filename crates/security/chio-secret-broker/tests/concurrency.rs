use std::sync::{Arc, Barrier};
use std::thread;
#[cfg(unix)]
use std::{fs, os::unix::fs::PermissionsExt};

use chio_secret_broker::budget::ExecutionQuota;
use chio_secret_broker::sqlite::SqliteAttemptStore;
use chio_secret_broker::store::{
    derive_attempt_ids, AttemptRegistration, AttemptStore, RegisterAttemptOutcome,
};
use chio_secret_broker::BrokerError;
use chio_test_support::prelude::*;

fn registration() -> AttemptRegistration {
    let request_digest = "a".repeat(64);
    AttemptRegistration {
        ids: derive_attempt_ids(
            "broker-capability",
            "invocation-a",
            "nonce-abcdefghijkl",
            &request_digest,
        )
        .test_expect("ids"),
        invocation_id: "invocation-a".to_string(),
        parent_capability_id: "parent-capability".to_string(),
        broker_capability_id: "broker-capability".to_string(),
        request_digest,
        request_canonical_digest: "d".repeat(64),
        proof_digest: "b".repeat(64),
        proof_key_id: "proof-key".to_string(),
        proof_nonce: "nonce-abcdefghijkl".to_string(),
        nonce_expires_at_unix_seconds: 100,
        quotas: vec![ExecutionQuota {
            key_id: "broker-quota".to_string(),
            maximum_executions: 1,
        }],
        authority_metadata_digest: "c".repeat(64),
        revocation_authority_domain: "combined-authority".to_string(),
    }
}

#[test]
fn deterministic_attempt_conflict_precedes_exact_retry_and_concurrent_replay() {
    let directory = tempfile::tempdir().test_expect("directory");
    #[cfg(unix)]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .test_expect("harden database directory");
    let trusted_directory =
        std::fs::canonicalize(directory.path()).test_expect("canonicalize database directory");
    let store = Arc::new(
        SqliteAttemptStore::open(trusted_directory.join("attempts.sqlite")).test_expect("store"),
    );
    let original = registration();
    assert!(matches!(
        store
            .register_attempt(&original, 20)
            .test_expect("register original attempt"),
        RegisterAttemptOutcome::Inserted(_)
    ));

    let mut conflicting = original.clone();
    conflicting.request_canonical_digest = "e".repeat(64);
    assert!(matches!(
        store.register_attempt(&conflicting, 20),
        Err(BrokerError::Conflict(message))
            if message == "deterministic attempt ID was reused with different input"
    ));
    assert!(matches!(
        store
            .register_attempt(&original, 20)
            .test_expect("retry exact attempt"),
        RegisterAttemptOutcome::ExactRetry(_)
    ));

    let barrier = Arc::new(Barrier::new(12));
    let mut workers = Vec::new();
    for _ in 0..12 {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            store.register_attempt(&registration(), 20)
        }));
    }
    for worker in workers {
        match worker.join().test_expect("worker").test_expect("register") {
            RegisterAttemptOutcome::Inserted(_) => {
                panic!("concurrent replay inserted a second nonce intent")
            }
            RegisterAttemptOutcome::ExactRetry(_) => {}
        }
    }
}
