#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Barrier};
use std::thread;

use chio_secret_broker::budget::ExecutionQuota;
use chio_secret_broker::sqlite::SqliteAttemptStore;
use chio_secret_broker::store::{
    derive_attempt_ids, AttemptRegistration, AttemptStore, RegisterAttemptOutcome,
};

fn registration() -> AttemptRegistration {
    let request_digest = "a".repeat(64);
    AttemptRegistration {
        ids: derive_attempt_ids(
            "broker-capability",
            "invocation-a",
            "nonce-abcdefghijkl",
            &request_digest,
        )
        .expect("ids"),
        invocation_id: "invocation-a".to_string(),
        parent_capability_id: "parent-capability".to_string(),
        broker_capability_id: "broker-capability".to_string(),
        request_digest,
        proof_digest: "b".repeat(64),
        proof_key_id: "proof-key".to_string(),
        proof_nonce: "nonce-abcdefghijkl".to_string(),
        nonce_expires_at_unix_seconds: 100,
        quotas: vec![ExecutionQuota {
            key_id: "broker-quota".to_string(),
            maximum_executions: 1,
        }],
        authority_metadata_digest: "c".repeat(64),
    }
}

#[test]
fn concurrent_replay_commits_one_nonce_intent() {
    let directory = tempfile::tempdir().expect("directory");
    let store = Arc::new(
        SqliteAttemptStore::open(directory.path().join("attempts.sqlite")).expect("store"),
    );
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
    let mut inserted = 0;
    for worker in workers {
        match worker.join().expect("worker").expect("register") {
            RegisterAttemptOutcome::Inserted(_) => inserted += 1,
            RegisterAttemptOutcome::ExactRetry(_) => {}
        }
    }
    assert_eq!(inserted, 1);
}
