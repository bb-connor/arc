#![cfg(test)]
use super::*;
use chio_core::receipt::{
    body::{ChioReceipt, ChioReceiptBody},
    decision::ToolCallAction,
    kinds::*,
};
use chio_test_support::prelude::*;
use serde_json::json;

#[path = "../../tests/support/session_certificate_corruption.rs"]
mod session_certificate_corruption;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Fixture {
    _directory: tempfile::TempDir,
    path: std::path::PathBuf,
    seed: std::path::PathBuf,
    public_key: std::path::PathBuf,
    output: std::path::PathBuf,
    key: chio_core::Keypair,
    store: chio_store_sqlite::SqliteReceiptStore,
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("actual-chio-store.sqlite3");
    let seed = directory.path().join("authority.seed");
    let public_key = directory.path().join("authority.pub");
    let output = directory.path().join("certificate.json");
    std::fs::write(&seed, "2a".repeat(32))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600))?;
    }
    let key = chio_core::Keypair::from_seed(&[42; 32]);
    std::fs::write(&public_key, key.public_key().to_hex())?;
    let store = chio_store_sqlite::SqliteReceiptStore::open(&path)?;
    Ok(Fixture {
        _directory: directory,
        path,
        seed,
        public_key,
        output,
        key,
        store,
    })
}

fn receipt(signer: &chio_core::Keypair, sequence: u64) -> ChioReceipt {
    ChioReceipt::sign(
        ChioReceiptBody {
            id: String::new(),
            timestamp: sequence,
            capability_id: "enforced-capability".into(),
            tool_server: "acp-proxy".into(),
            tool_name: "read".into(),
            action: ToolCallAction::from_parameters(json!({"path":"/example","sequence":sequence}))
                .test_unwrap(),
            decision: None,
            receipt_kind: ReceiptKind::TraceObservation,
            boundary_class: BoundaryClass::DetectOnly,
            observation_outcome: Some(ObservationOutcome::Observed),
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: "content".into(),
            policy_hash: "policy".into(),
            evidence: Vec::new(),
            metadata: Some(json!({"acp":{"sessionId":"target_%"}})),
            trust_level: TrustLevel::Verified,
            kernel_key: signer.public_key(),
            bbs_projection_version: None,
            tenant_id: None,
        },
        signer,
    )
    .test_unwrap()
}

fn append(f: &Fixture, count: u64) -> Result<(), Box<dyn std::error::Error>> {
    for sequence in 1..=count {
        f.store
            .append_chio_receipt_returning_seq(&receipt(&f.key, sequence))?;
    }
    f.store.create_next_receipt_checkpoint(count, &f.key)?;
    Ok(())
}

fn generate(f: &Fixture) -> Result<ComplianceCertificate, Box<dyn std::error::Error>> {
    cmd_cert_generate("target_%", &f.path, 0, Some(&f.output), Some(&f.seed), true)?;
    Ok(serde_json::from_slice(&std::fs::read(&f.output)?)?)
}

#[test]
fn session_receipts_cli_generates_from_authenticated_chio_store() -> TestResult {
    let f = fixture()?;
    append(&f, 1)?;
    let certificate = generate(&f)?;
    assert_eq!(certificate.body.receipt_count, 1);
    assert_eq!(certificate.body.invocation_count, Some(0));
    assert!(!certificate.body.scope_compliant && !certificate.body.guards_compliant);
    assert!(matches!(
        certificate.body.coverage,
        Some(
            chio_acp_proxy::ComplianceCoverage::RetainedSnapshotReference {
                snapshot_end_entry_seq: 1,
                ..
            }
        )
    ));
    cmd_cert_verify(&f.output, true, Some(&f.path), &f.public_key, true)?;
    Ok(())
}

#[test]
fn certificate_collection_certifies_a_session_beyond_the_proof_artifact_limit() -> TestResult {
    let f = fixture()?;
    append(&f, 4_097)?;
    let snapshot = load_session_receipts(&f.path, "target_%", &f.key.public_key(), None)?;
    let entries = certificate_entries(&snapshot);
    assert_eq!(entries.len(), 4_097);
    assert_eq!((entries[0].seq, entries[4_096].seq), (1, 4_097));
    let certificate = generate(&f)?;
    assert_eq!(certificate.body.receipt_count, 4_097);
    assert_eq!(certificate.body.invocation_count, Some(0));
    cmd_cert_verify(&f.output, true, Some(&f.path), &f.public_key, true)?;
    Ok(())
}

#[test]
fn certificate_collection_isolates_unrelated_oversized_receipt_bodies() -> TestResult {
    let f = fixture()?;
    let mut body = receipt(&f.key, 1).body();
    body.id.clear();
    body.metadata =
        Some(json!({"acp":{"sessionId":"another-session"},"padding":"x".repeat(1024*1024+1)}));
    f.store
        .append_chio_receipt_returning_seq(&ChioReceipt::sign(body, &f.key)?)?;
    f.store
        .append_chio_receipt_returning_seq(&receipt(&f.key, 2))?;
    f.store.create_next_receipt_checkpoint(2, &f.key)?;
    let snapshot = load_session_receipts(&f.path, "target_%", &f.key.public_key(), None)?;
    assert_eq!(snapshot.receipts().len(), 1);
    assert!(load_session_receipts(&f.path, "another-session", &f.key.public_key(), None).is_err());
    Ok(())
}

#[test]
fn certificate_collection_cannot_hide_membership_behind_duplicate_or_conflicting_fields(
) -> TestResult {
    let f = fixture()?;
    append(&f, 1)?;
    session_certificate_corruption::corrupt_temporary_tool_receipt(
        &f.path,
        "UPDATE chio_tool_receipts SET raw_json=?1",
        [r#"{"metadata":{"acp":{"sessionId":"other","sessionId":"target_%"}}}"#],
    )?;
    assert!(load_session_receipts(&f.path, "target_%", &f.key.public_key(), None).is_err());
    Ok(())
}

#[test]
fn certificate_collection_refuses_unknown_membership_without_trusting_capability_id() -> TestResult
{
    let f = fixture()?;
    append(&f, 1)?;
    session_certificate_corruption::corrupt_temporary_tool_receipt(
        &f.path,
        "UPDATE chio_tool_receipts SET raw_json='{bad', capability_id='acp-session:other'",
        [],
    )?;
    assert!(load_session_receipts(&f.path, "target_%", &f.key.public_key(), None).is_err());
    Ok(())
}

#[test]
fn certificate_collection_reports_private_row_context_and_preserves_gaps() -> TestResult {
    let f = fixture()?;
    f.store
        .append_chio_receipt_returning_seq(&receipt(&f.key, 1))?;
    let mut other = receipt(&f.key, 2).body();
    other.id.clear();
    other.metadata = Some(json!({"receipt_context":{"session_id":"other"}}));
    f.store
        .append_chio_receipt_returning_seq(&ChioReceipt::sign(other, &f.key)?)?;
    f.store
        .append_chio_receipt_returning_seq(&receipt(&f.key, 3))?;
    f.store.create_next_receipt_checkpoint(3, &f.key)?;
    let snapshot = load_session_receipts(&f.path, "target_%", &f.key.public_key(), None)?;
    assert_eq!(
        snapshot
            .receipts()
            .iter()
            .map(|entry| entry.seq)
            .collect::<Vec<_>>(),
        [1, 3]
    );
    let certificate = generate(&f)?;
    assert_eq!(certificate.body.receipt_count, 2);
    cmd_cert_verify(&f.output, true, Some(&f.path), &f.public_key, true)?;
    Ok(())
}

#[test]
fn session_receipts_cli_preserves_interleaved_archived_and_live_history() -> TestResult {
    let f = fixture()?;
    f.store
        .append_chio_receipt_returning_seq(&receipt(&f.key, 1))?;
    let mut other = receipt(&f.key, 2).body();
    other.id.clear();
    other.metadata = Some(json!({"receipt_context":{"session_id":"other"}}));
    f.store
        .append_chio_receipt_returning_seq(&ChioReceipt::sign(other, &f.key)?)?;
    f.store
        .append_chio_receipt_returning_seq(&receipt(&f.key, 3))?;
    f.store.create_next_receipt_checkpoint(3, &f.key)?;
    let archive = f._directory.path().join("archive.sqlite3");
    assert_eq!(
        f.store
            .archive_receipts_before(4, archive.to_str().test_unwrap())?,
        3
    );
    f.store
        .append_chio_receipt_returning_seq(&receipt(&f.key, 4))?;
    f.store.create_next_receipt_checkpoint(1, &f.key)?;
    let snapshot = load_session_receipts(&f.path, "target_%", &f.key.public_key(), None)?;
    assert_eq!(
        snapshot
            .receipts()
            .iter()
            .map(|row| (row.seq, row.entry_seq))
            .collect::<Vec<_>>(),
        [(1, 1), (3, 3), (4, 4)]
    );
    assert_eq!(snapshot.coverage().archived_through_entry_seq, 3);
    assert_eq!(snapshot.coverage().snapshot_end_entry_seq, 4);
    let certificate = generate(&f)?;
    assert_eq!(certificate.body.receipt_count, 3);
    assert_eq!(certificate.body.invocation_count, Some(0));
    cmd_cert_verify(&f.output, true, Some(&f.path), &f.public_key, true)?;
    Ok(())
}

#[test]
fn certificate_collection_rejects_uninspectable_rows_before_allocation() -> TestResult {
    let f = fixture()?;
    append(&f, 1)?;
    session_certificate_corruption::corrupt_temporary_tool_receipt(
        &f.path,
        "UPDATE chio_tool_receipts SET raw_json=CAST(zeroblob(16777217) AS TEXT)",
        [],
    )?;
    assert!(load_session_receipts(&f.path, "target_%", &f.key.public_key(), None).is_err());
    Ok(())
}

#[test]
fn session_receipts_same_snapshot_reference_cannot_certify_a_truncated_cli_set() -> TestResult {
    let f = fixture()?;
    append(&f, 2)?;
    let snapshot = load_session_receipts(&f.path, "target_%", &f.key.public_key(), None)?;
    let entries = certificate_entries(&snapshot);
    let config = profile::load_profile(None, &f.key.public_key(), None)?;
    // The portable API authenticates this declared supplied set, not the corpus.
    let truncated = chio_acp_proxy::generate_compliance_certificate_with_coverage(
        "target_%",
        &entries[..1],
        &config,
        &f.key,
        &chio_acp_proxy::AcpClock::default(),
        snapshot_reference(&snapshot),
    )?;
    let portable = verify_compliance_certificate(
        &truncated,
        VerificationMode::FullBundle,
        Some(&entries[..1]),
        &config,
    );
    assert!(portable.passed);
    assert_eq!(
        portable.verification_scope,
        CertificateVerificationScope::CommittedReceiptSet
    );
    std::fs::write(&f.output, serde_json::to_vec_pretty(&truncated)?)?;
    assert!(
        cmd_cert_verify(&f.output, true, Some(&f.path), &f.public_key, true).is_err(),
        "same coverage masked missing signed session rows"
    );
    Ok(())
}

#[test]
fn session_receipts_changed_current_snapshot_requires_a_fresh_certificate() -> TestResult {
    let f = fixture()?;
    append(&f, 1)?;
    generate(&f)?;
    f.store
        .append_chio_receipt_returning_seq(&receipt(&f.key, 2))?;
    f.store.create_next_receipt_checkpoint(1, &f.key)?;
    assert!(cmd_cert_verify(&f.output, true, Some(&f.path), &f.public_key, true).is_err());
    Ok(())
}

#[test]
fn session_receipts_explicit_profile_checks_real_tool_targets_and_guard_evidence() -> TestResult {
    let f = fixture()?;
    let mut body = receipt(&f.key, 1).body();
    body.id.clear();
    body.decision = Some(chio_core::receipt::decision::Decision::Allow);
    body.receipt_kind = ReceiptKind::MediatedDecision;
    body.boundary_class = BoundaryClass::Prevent;
    body.observation_outcome = None;
    body.trust_level = TrustLevel::Mediated;
    body.evidence = vec![chio_core::receipt::metadata::GuardEvidence {
        guard_name: "required-guard".into(),
        verdict: true,
        details: None,
    }];
    f.store
        .append_chio_receipt_returning_seq(&ChioReceipt::sign(body, &f.key)?)?;
    f.store.create_next_receipt_checkpoint(1, &f.key)?;
    let profile_path = f._directory.path().join("profile.json");
    std::fs::write(&profile_path, json!({"budget_limit":1,"required_guards":["required-guard"],"tool_targets":[{"server_id":"acp-proxy","tool_name":"read"}]}).to_string())?;
    cmd_cert_generate_with_profile(CertificateGenerateOptions {
        session_id: "target_%",
        receipt_db: &f.path,
        budget_limit: 0,
        output: Some(&f.output),
        authority_seed_file: Some(&f.seed),
        json_output: true,
        profile_path: Some(&profile_path),
    })?;
    let certificate: ComplianceCertificate = serde_json::from_slice(&std::fs::read(&f.output)?)?;
    assert!(
        certificate.body.scope_compliant
            && certificate.body.guards_compliant
            && certificate.body.budget_compliant
    );
    cmd_cert_verify_with_profile(CertificateVerifyOptions {
        certificate_path: &f.output,
        full: true,
        receipt_db: Some(&f.path),
        trusted_kernel_pubkey: &f.public_key,
        json_output: true,
        profile_path: Some(&profile_path),
    })?;
    std::fs::write(&profile_path, json!({"budget_limit":1,"required_guards":["required-guard"],"tool_targets":[{"server_id":"different-server","tool_name":"read"}]}).to_string())?;
    assert!(cmd_cert_verify_with_profile(CertificateVerifyOptions {
        certificate_path: &f.output,
        full: true,
        receipt_db: Some(&f.path),
        trusted_kernel_pubkey: &f.public_key,
        json_output: true,
        profile_path: Some(&profile_path)
    })
    .is_err());
    Ok(())
}
