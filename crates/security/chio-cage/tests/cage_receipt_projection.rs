//! The `cage_receipt` projection commits every argument-derived digest, binds the receipt's
//! policy hash to the profile digest commitment, and binds to the raw body.

use std::cell::Cell;

use chio_cage::{
    CageEnforcementFailure, CageEnforcementFailureCode, CageEnforcementRecord, CageReceiptBindings,
    CageReceiptBody, CageReceiptProjection, EnforcementPrepared, ExecTransitionObserved,
    ExecutionIdentity, FullyEnforcedEvidence, ObservedRulesetStatus, ProcessExitEvidence,
    SandboxArchitecture, SeccompEnforcementStatus, ENFORCEMENT_PREPARED_SCHEMA,
    EXEC_TRANSITION_OBSERVED_SCHEMA, NONO_PATCH_VERSION, PINNED_NONO_VERSION,
    PINNED_SECCOMPILER_VERSION,
};
use chio_core::receipt::metadata::{metadata_salt_ref, MetadataOpenings, MetadataValue};
use chio_core::rng::{Rng, RngError};
use chio_test_support::prelude::*;

struct CountingRng(Cell<u64>);

impl Rng for CountingRng {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RngError> {
        let next = self.0.get().wrapping_add(1);
        self.0.set(next);
        for (index, byte) in dest.iter_mut().enumerate() {
            *byte = next.to_le_bytes()[index % 8] ^ u8::try_from(index % 256).unwrap_or(0);
        }
        Ok(())
    }
}

fn rng(seed: u64) -> CountingRng {
    CountingRng(Cell::new(seed))
}

fn digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn identity() -> chio_cage::FileIdentity {
    serde_json::from_value(serde_json::json!({
        "device": 1,
        "inode": 2,
        "mount_id": 3,
        "mode": 0o100700,
        "uid": 1000,
        "gid": 1000,
        "kind": "regular_file"
    }))
    .test_expect("valid identity")
}

fn prepared() -> EnforcementPrepared {
    EnforcementPrepared {
        schema: ENFORCEMENT_PREPARED_SCHEMA.to_string(),
        process_id: 4242,
        manifest_digest: digest('1'),
        profile_digest: digest('2'),
        plan_digest: digest('3'),
        fd_table_digest: digest('4'),
        helper_binding_digest: digest('5'),
        target_binding_digest: digest('6'),
        target_identity: identity(),
        applied_execution_identity: ExecutionIdentity::new(10001, 10001, vec![10002])
            .test_expect("valid execution identity"),
        nono_version: PINNED_NONO_VERSION.to_string(),
        nono_patch_version: NONO_PATCH_VERSION.to_string(),
        landlock_abi: 6,
        landlock_filesystem_status: ObservedRulesetStatus::FullyEnforced,
        landlock_network_status: ObservedRulesetStatus::FullyEnforced,
        seccompiler_version: PINNED_SECCOMPILER_VERSION.to_string(),
        seccomp_status: SeccompEnforcementStatus::FullyEnforced,
        seccomp_architecture: SandboxArchitecture::X86_64,
        seccomp_filter_digest: digest('7'),
        trace_session_digest: digest('8'),
        prepared_at_unix_ms: 1_000,
    }
}

fn exec_transition() -> ExecTransitionObserved {
    ExecTransitionObserved {
        schema: EXEC_TRANSITION_OBSERVED_SCHEMA.to_string(),
        process_id: 4242,
        trace_session_digest: digest('8'),
        target_binding_digest: digest('6'),
        target_identity: identity(),
        observed_at_unix_ms: 1_001,
    }
}

fn exited_body(attempt_id: &str) -> CageReceiptBody {
    let evidence = FullyEnforcedEvidence::new(prepared(), exec_transition(), true)
        .test_expect("complete evidence");
    let exit = ProcessExitEvidence {
        process_id: 4242,
        exit_code: Some(0),
        signal: None,
        exited_at_unix_ms: 1_002,
    };
    let record = CageEnforcementRecord::exited(evidence, exit).test_expect("exit record");
    CageReceiptBody::new(attempt_id, None, record, 900, 1_002).test_expect("exit body")
}

fn rejected_body() -> CageReceiptBody {
    let failure = CageEnforcementFailure::new(CageEnforcementFailureCode::InvalidPlan, "admission")
        .test_unwrap();
    let record = CageEnforcementRecord::rejected(failure).test_unwrap();
    CageReceiptBody::new("attempt-reject-7f3a", None, record, 1_000, 2_000).test_unwrap()
}

fn encode(projection: &CageReceiptProjection) -> String {
    chio_core::canonical_json_string(projection).test_unwrap()
}

#[test]
fn cage_projection_commits_argument_digests_and_binds_the_policy_hash() {
    let body = exited_body("attempt-exit-7f3a");
    let (projection, openings) =
        CageReceiptProjection::project(&body, &digest('2'), &rng(0)).test_unwrap();
    assert!(projection.matches(&body, &digest('2'), &openings));
    let encoded = encode(&projection);
    for raw in [
        digest('2'),
        digest('3'),
        digest('4'),
        digest('7'),
        digest('8'),
        "attempt-exit-7f3a".to_string(),
        "\"process_id\":4242".to_string(),
        "10002".to_string(),
    ] {
        assert!(!encoded.contains(&raw), "projection carries {raw}");
    }
    for kept in [digest('1'), digest('5'), digest('6')] {
        assert!(encoded.contains(&kept), "projection drops {kept}");
    }
    assert_eq!(projection.schema, chio_cage::CAGE_RECEIPT_METADATA_SCHEMA);
    assert_eq!(
        projection.profile_digest.salt_ref().as_str(),
        "metadata.cage_receipt.profile_digest"
    );
    assert_eq!(projection.policy_hash().len(), 64);
    assert_ne!(projection.policy_hash(), digest('2'));
    let enforcement = projection.enforcement.as_ref().test_unwrap();
    let exit = projection.exit.as_ref().test_unwrap();
    assert_eq!(enforcement.process_id, exit.process_id);
    assert_eq!(exit.exit_code, Some(0));
    let decoded: CageReceiptProjection = serde_json::from_str(&encoded).test_unwrap();
    assert_eq!(decoded, projection);
}

#[test]
fn admitted_policy_digest_shares_the_profile_commitment_only_when_equal() {
    let mut equal = exited_body("attempt-admitted-equal");
    equal.admitted_policy_digest = Some(digest('2'));
    let (projection, _) =
        CageReceiptProjection::project(&equal, &digest('2'), &rng(0)).test_unwrap();
    assert_eq!(
        projection.admitted_policy_digest.as_ref(),
        Some(&projection.profile_digest)
    );

    let mut other = exited_body("attempt-admitted-other");
    other.admitted_policy_digest = Some(digest('9'));
    let (projection, _) =
        CageReceiptProjection::project(&other, &digest('2'), &rng(0)).test_unwrap();
    let admitted = projection.admitted_policy_digest.as_ref().test_unwrap();
    assert_eq!(
        admitted.salt_ref().as_str(),
        "metadata.cage_receipt.admitted_policy_digest"
    );
    assert!(!encode(&projection).contains(&digest('9')));
}

#[test]
fn cage_projection_refuses_other_bodies_policy_hashes_and_openings() {
    let body = exited_body("attempt-match");
    let (projection, openings) =
        CageReceiptProjection::project(&body, &digest('2'), &rng(0)).test_unwrap();
    assert!(!projection.matches(&exited_body("attempt-other"), &digest('2'), &openings));
    assert!(!projection.matches(&body, &digest('9'), &openings));
    assert!(!projection.matches(&body, &digest('2'), &MetadataOpenings::new()));
    let (_, other_openings) =
        CageReceiptProjection::project(&body, &digest('2'), &rng(1_000)).test_unwrap();
    assert!(!projection.matches(&body, &digest('2'), &other_openings));
    let mut padded = openings.clone();
    padded
        .commit_value(
            metadata_salt_ref("cage_receipt", "unused").test_unwrap(),
            MetadataValue::from_json(&"unused").test_unwrap(),
            &rng(5_000),
        )
        .test_unwrap();
    assert!(!projection.matches(&body, &digest('2'), &padded));
}

#[test]
fn cage_projection_refuses_bindings_for_another_profile() {
    let failure = CageEnforcementFailure::new(
        CageEnforcementFailureCode::SeccompInstallFailed,
        "bootstrap",
    )
    .test_unwrap();
    let record = CageEnforcementRecord::bootstrap_failed(failure).test_unwrap();
    let bindings = CageReceiptBindings::from_prepared(&prepared());
    let body =
        CageReceiptBody::new("attempt-bootstrap", Some(bindings), record, 900, 1_001).test_unwrap();
    assert!(CageReceiptProjection::project(&body, &digest('2'), &rng(0)).is_ok());
    assert!(CageReceiptProjection::project(&body, &digest('9'), &rng(0)).is_err());
}

#[test]
fn raw_opening_recomputes_every_field_commitment() {
    let body = exited_body("attempt-raw");
    let (projection, openings) =
        CageReceiptProjection::project(&body, &digest('2'), &rng(0)).test_unwrap();
    assert_eq!(
        projection.raw.salt_ref().as_str(),
        "metadata.cage_receipt.raw"
    );
    assert_eq!(
        projection.open_raw(&digest('2'), &openings).test_unwrap(),
        body
    );

    let other = exited_body("attempt-raw-other");
    let (_, other_openings) =
        CageReceiptProjection::project(&other, &digest('2'), &rng(9_000)).test_unwrap();
    assert!(projection.open_raw(&digest('2'), &other_openings).is_err());
    assert!(projection.open_raw(&digest('9'), &openings).is_err());
}

#[test]
fn rejected_receipt_projects_its_closed_failure() {
    let body = rejected_body();
    let (projection, openings) =
        CageReceiptProjection::project(&body, &digest('2'), &rng(0)).test_unwrap();
    assert!(projection.matches(&body, &digest('2'), &openings));
    assert!(projection.bindings.is_none());
    assert!(projection.enforcement.is_none());
    assert!(projection.exit.is_none());
    assert_eq!(
        projection.failure.as_ref().map(|failure| failure.code),
        Some(CageEnforcementFailureCode::InvalidPlan)
    );
    assert!(!encode(&projection).contains("attempt-reject-7f3a"));
}
