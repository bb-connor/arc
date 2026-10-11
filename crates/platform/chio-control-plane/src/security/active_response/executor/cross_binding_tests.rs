//! Existing-record serialization checks at the private executor boundary.
use super::super::tests::Harness;
use super::*;
use chio_core::{canonical_json_bytes, sha256};
use chio_security_types::ports::CanonicalBody;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn commit_without_effects(
    harness: &Harness,
    raw: &RawActiveResponseExecutionRequest,
) -> Result<ResponseDispatchRecord, Box<dyn std::error::Error>> {
    let prepared = raw.prepare_dispatch(
        ResponseDispatchLease {
            lease_owner_id: LeaseOwnerId::new("cross-binding-reader")?,
            lease_expires_at_unix_ms: raw.authorized_at_unix_ms + 20_000,
        },
        raw.authorized_at_unix_ms + 1_000,
    )?;
    match harness.executor.store.commit_dispatch(&prepared)? {
        ResponseDispatchCommitOutcome::Committed(record) => Ok(record),
        ResponseDispatchCommitOutcome::Existing(_) => {
            Err("initial fixture dispatch already existed".into())
        }
    }
}

fn recanonicalize(
    record: &mut ResponseDispatchRecord,
    fingerprint: Option<Digest32>,
) -> TestResult {
    let mut snapshot = decode_response_record(&record.response_plan)?;
    let binding = snapshot
        .execution_dispatch
        .as_mut()
        .ok_or("execution binding missing")?;
    let schema = if fingerprint.is_some() {
        chio_security_types::ports::RESPONSE_DISPATCH_AUTHORIZATION_SCHEMA_VERSION
    } else {
        1
    };
    binding.schema_version = schema;
    binding.admission_artifact_fingerprint = fingerprint;
    binding.validate_for_plan(&snapshot.plan)?;
    snapshot.dispatch_authorization_hash = None;
    record.authorization.body.schema_version = schema;
    record.authorization.body.admission_artifact_fingerprint = fingerprint;
    record.authorization.body.response_body_hash =
        Digest32::new(*sha256(&canonical_json_bytes(&snapshot)?).as_bytes());
    let authorization = canonical_json_bytes(&record.authorization.body)?;
    record.authorization.body_hash = Digest32::new(*sha256(&authorization).as_bytes());
    record.authorization.canonical_body = CanonicalBody::new(authorization)?;
    snapshot.dispatch_authorization_hash = Some(record.authorization.body_hash);
    let response = canonical_json_bytes(&snapshot)?;
    record.response_plan.body_hash = Digest32::new(*sha256(&response).as_bytes());
    record.response_plan.canonical_body = CanonicalBody::new(response)?;
    Ok(())
}

fn pin_bytes(harness: &Harness) -> Result<Vec<u8>, rusqlite::Error> {
    rusqlite::Connection::open(&harness.database_path)?.query_row(
        "SELECT prepared_binding_body FROM security_response_automatic_preparations",
        [],
        |row| row.get(0),
    )
}

fn assert_original_unchanged(
    harness: &Harness,
    record: &ResponseDispatchRecord,
    pin: &[u8],
) -> TestResult {
    assert_eq!(
        harness
            .executor
            .store
            .load_dispatch(&record.authorization.body.key)?,
        ResponseDispatchLoadOutcome::Found(Box::new(record.clone()))
    );
    assert_eq!(pin_bytes(harness)?, pin);
    assert_eq!(harness.effect_executions(), 0);
    Ok(())
}

fn reject_other_binding(fingerprint: Option<Digest32>) -> TestResult {
    let harness = Harness::new();
    let raw = harness.automatic_request();
    let validated = harness.executor.validate_execution_request(raw.clone())?;
    let original = commit_without_effects(&harness, &raw)?;
    let pin = pin_bytes(&harness)?;
    harness
        .executor
        .validate_existing_dispatch(&validated, &original)?;
    let mut alternate = original.clone();
    recanonicalize(&mut alternate, fingerprint)?;
    assert_ne!(
        alternate.authorization.body.admission_artifact_fingerprint,
        raw.admission_artifact_fingerprint
    );
    assert_eq!(
        alternate.authorization.body.key,
        original.authorization.body.key
    );
    assert_eq!(alternate.initial_work, original.initial_work);
    // The two stored artifacts are internally coherent. Only their equality
    // with the independently validated original request can refuse this case.
    harness
        .executor
        .response_executor
        .validate_dispatch_authorization(&alternate.response_plan, &alternate.authorization)?;
    let refused = harness
        .executor
        .validate_existing_dispatch(&validated, &alternate);
    assert!(
        matches!(&refused, Err(ActiveResponseExecutorError::RejectedBeforeCommit(reason))
        if reason == "dispatch id is already bound to a different active-response command"),
        "different coherent binding was accepted: {refused:?}"
    );
    assert_original_unchanged(&harness, &original, &pin)
}

#[test]
fn existing_dispatch_rejects_other_coherent_artifact_fingerprint() -> TestResult {
    reject_other_binding(Some(Digest32::new([36; 32])))
}

#[test]
fn existing_dispatch_rejects_coherent_legacy_downgrade_of_bound_request() -> TestResult {
    reject_other_binding(None)
}

#[test]
fn existing_dispatch_accepts_exact_coherent_legacy_request() -> TestResult {
    let harness = Harness::new();
    let mut raw = harness.governed_request();
    raw.origin = ActiveResponseExecutionOrigin::CommittedAdmission;
    raw.admission_artifact_fingerprint = None;
    raw.dispatch_id = derive_active_response_dispatch_id(
        &raw.response_plan,
        &raw.executor_authority,
        &raw.authorization_capability_hash,
        &raw.governed_intent_hash,
        &raw.policy_decision_hash,
        raw.authorized_at_unix_ms,
        &raw.approval,
    )?;
    let validated = harness.executor.validate_execution_request(raw.clone())?;
    let record = commit_without_effects(&harness, &raw)?;
    assert_eq!(record.authorization.body.schema_version, 1);
    assert_eq!(
        record.authorization.body.admission_artifact_fingerprint,
        None
    );
    assert!(
        !std::str::from_utf8(record.authorization.canonical_body.as_bytes())?
            .contains("admission_artifact_fingerprint")
    );
    harness
        .executor
        .validate_existing_dispatch(&validated, &record)?;
    assert_eq!(
        harness
            .executor
            .store
            .load_dispatch(&record.authorization.body.key)?,
        ResponseDispatchLoadOutcome::Found(Box::new(record.clone()))
    );
    assert_eq!(harness.effect_executions(), 0);
    let rows: i64 = rusqlite::Connection::open(&harness.database_path)?.query_row(
        "SELECT COUNT(*) FROM security_response_automatic_preparations",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(rows, 0);
    Ok(())
}
