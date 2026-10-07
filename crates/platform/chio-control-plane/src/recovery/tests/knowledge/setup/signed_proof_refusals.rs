//! Incoming signed proofs cannot turn healthy native custody into a store failure.
use super::*;
use chio_kernel::admission_operation::{
    AdmissionOperationStoreError, ADMISSION_RECEIPT_METADATA_KEY,
};

struct QualifiedNativeSetup {
    fixture: KnowledgeFixture,
    report: chio_core_types::recovery::SignedRecoverySetupReportV1,
}

async fn qualified_native_setup() -> TestResult<Box<QualifiedNativeSetup>> {
    let mut evidence = Box::pin(begin_restart_proof()).await?;
    let fixture = KnowledgeFixture::from(RecoveryFixture::open(
        evidence.path.clone(),
        evidence.directory.take(),
        false,
    )?)?;
    let service = setup(&fixture, &evidence.workflow)?;
    let report = service.qualify(&fixture.f.control, &evidence.probe).await?;
    assert!(report.verify_signature()?);
    assert_eq!(report.body().benign_operation, evidence.operation);
    assert_eq!(external_count(&fixture.f.path)?, evidence.effects);
    assert_eq!(
        fixture.f.process.process("root")?.tree_calls,
        evidence.tree_calls
    );
    assert_eq!(
        fixture
            .f
            .authority
            .admission_operation_store()
            .accept_setup_report(&report, &fixture.f.authority.mutation_fence(), now_ms()?,)?,
        report,
        "the actual current report must replay from healthy native custody",
    );
    Ok(Box::new(QualifiedNativeSetup { fixture, report }))
}

#[tokio::test]
async fn setup_report_with_an_unpinned_signer_is_an_authority_refusal_without_mutation(
) -> TestResult {
    let ready = Box::pin(qualified_native_setup()).await?;
    let f = &ready.fixture;
    let supplied = chio_core_types::recovery::SignedRecoverySetupReportV1::sign(
        ready.report.body().clone(),
        &Keypair::from_seed(&[210; 32]),
    )?;
    assert!(supplied.verify_signature()?);
    assert_ne!(supplied.authority_key(), ready.report.authority_key());
    let before = super::journal_availability::retained_setup_records(f)?;
    let calls = f.f.process.process("root")?.tree_calls;
    let effects = external_count(&f.f.path)?;
    let result =
        f.f.authority
            .admission_operation_store()
            .accept_setup_report(&supplied, &f.f.authority.mutation_fence(), now_ms()?);
    assert!(
        matches!(
            result,
            Err(AdmissionOperationStoreError::RecoveryAuthorityDenied)
        ),
        "a correctly signed caller proof from another key is an authority refusal",
    );
    assert_eq!(
        super::journal_availability::retained_setup_records(f)?,
        before
    );
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    assert_eq!(external_count(&f.f.path)?, effects);
    Ok(())
}

#[tokio::test]
async fn setup_report_with_a_changed_signed_body_is_an_authority_refusal_without_mutation(
) -> TestResult {
    let ready = Box::pin(qualified_native_setup()).await?;
    let f = &ready.fixture;
    let mut body = ready.report.body().clone();
    body.benign_receipt = SourceDigest::from_bytes([88; 32]);
    assert_ne!(body.benign_receipt, ready.report.body().benign_receipt);
    let supplied = chio_core_types::recovery::SignedRecoverySetupReportV1::sign(
        body,
        &Keypair::from_seed(&[211; 32]),
    )?;
    assert!(supplied.verify_signature()?);
    assert_eq!(supplied.authority_key(), ready.report.authority_key());
    let before = super::journal_availability::retained_setup_records(f)?;
    let calls = f.f.process.process("root")?.tree_calls;
    let effects = external_count(&f.f.path)?;
    let result =
        f.f.authority
            .admission_operation_store()
            .accept_setup_report(&supplied, &f.f.authority.mutation_fence(), now_ms()?);
    assert!(
        matches!(
            result,
            Err(AdmissionOperationStoreError::RecoveryAuthorityDenied)
        ),
        "a changed caller proof is a refusal while the retained completion stays healthy",
    );
    assert_eq!(
        super::journal_availability::retained_setup_records(f)?,
        before
    );
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    assert_eq!(external_count(&f.f.path)?, effects);
    Ok(())
}

#[tokio::test]
async fn setup_probe_conflicting_with_retained_evidence_is_an_authority_refusal_without_mutation(
) -> TestResult {
    let ready = Box::pin(qualified_native_setup()).await?;
    let f = &ready.fixture;
    let probe = &ready.report.body().probe;
    let actor = f.actor(RecoveryPermission::Inspect)?;
    let record = f.f.record(&probe.benign_workflow)?;
    let benign =
        f.f.kernel
            .replay_recovery_result(&actor, &probe.benign_workflow)?
            .receipt;
    assert!(benign.verify_signature()? && benign.is_allowed());
    let receipts = super::denied_mediation::retained_receipts(f)?;
    let denied = receipts
        .iter()
        .find(|receipt| {
            receipt.is_denied()
                && receipt.metadata.as_ref().and_then(|metadata| {
                    metadata
                        .get(ADMISSION_RECEIPT_METADATA_KEY)
                        .and_then(|admission| admission.get("request_id"))
                        .and_then(serde_json::Value::as_str)
                }) == Some(probe.denied_command.as_str())
        })
        .ok_or("the actual compensated native counterpart receipt must remain retained")?;
    assert!(denied.evidence.iter().any(|guard| {
        guard.guard_name == "native-flow-resolver"
            && !guard.verdict
            && guard.details.as_deref() == Some("policy_flow_violation")
    }));
    let mut denied_request = record.seed.clone();
    denied_request.request_id = probe.denied_command.as_str().to_owned();
    denied_request.declassification_grant = None;
    denied_request.execution_nonce = None;
    let mut body = probe.clone();
    body.probe_id = ChallengeId::new("another-signed-native-probe")?;
    let supplied = chio_core_types::recovery::SignedRecoverySetupProbeV1::sign(
        body,
        &Keypair::from_seed(&[211; 32]),
    )?;
    assert!(supplied.verify_signature()?);
    assert_ne!(supplied.body(), probe);
    let before = super::journal_availability::retained_setup_records(f)?;
    let calls = f.f.process.process("root")?.tree_calls;
    let effects = external_count(&f.f.path)?;
    let result =
        f.f.authority
            .admission_operation_store()
            .commit_setup_probe(
                &actor,
                &chio_store_sqlite::admission_operation_store::NativeSetupProbeEvidenceV1 {
                    probe: &supplied,
                    benign: &benign,
                    denied_request: &denied_request,
                    denied,
                },
                &f.f.authority.mutation_fence(),
                now_ms()?,
            );
    assert!(
        matches!(
            result,
            Err(AdmissionOperationStoreError::RecoveryAuthorityDenied)
        ),
        "conflicting incoming signed evidence must not become a physical store failure",
    );
    assert_eq!(
        super::journal_availability::retained_setup_records(f)?,
        before
    );
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    assert_eq!(external_count(&f.f.path)?, effects);
    Ok(())
}

#[tokio::test]
async fn setup_structurally_invalid_incoming_proofs_are_authority_refusals_without_mutation(
) -> TestResult {
    let ready = Box::pin(qualified_native_setup()).await?;
    let f = &ready.fixture;
    let actor = f.actor(RecoveryPermission::Inspect)?;
    let benign =
        f.f.kernel
            .replay_recovery_result(&actor, &ready.report.body().probe.benign_workflow)?
            .receipt;
    assert!(benign.is_allowed() && benign.verify_signature()?);
    let valid_probe = chio_core_types::recovery::SignedRecoverySetupProbeV1::sign(
        ready.report.body().probe.clone(),
        &Keypair::from_seed(&[211; 32]),
    )?;
    assert!(valid_probe.verify_signature()?);
    assert_eq!(valid_probe.body(), &ready.report.body().probe);

    let mut report_wire = serde_json::to_value(&ready.report)?;
    let current_fence = report_wire["body"]["current_serving_fence"].clone();
    report_wire["body"]["previous_serving_fence"] = current_fence;
    let malformed_report: chio_core_types::recovery::SignedRecoverySetupReportV1 =
        serde_json::from_value(report_wire)?;
    assert!(matches!(
        malformed_report.verify_signature(),
        Err(chio_core_types::Error::InvalidSignature(_))
    ));
    let mut probe_wire = serde_json::to_value(&valid_probe)?;
    let issued_at = probe_wire["body"]["issued_at_unix_ms"].clone();
    probe_wire["body"]["expires_at_unix_ms"] = issued_at;
    let malformed_probe: chio_core_types::recovery::SignedRecoverySetupProbeV1 =
        serde_json::from_value(probe_wire)?;
    assert!(matches!(
        malformed_probe.verify_signature(),
        Err(chio_core_types::Error::InvalidSignature(_))
    ));

    let before = super::journal_availability::retained_setup_records(f)?;
    let calls = f.f.process.process("root")?.tree_calls;
    let effects = external_count(&f.f.path)?;
    let report_result =
        f.f.authority
            .admission_operation_store()
            .accept_setup_report(
                &malformed_report,
                &f.f.authority.mutation_fence(),
                now_ms()?,
            );
    let probe_result =
        f.f.authority
            .admission_operation_store()
            .prepare_setup_report(
                &actor,
                &malformed_probe,
                &benign,
                &f.f.authority.mutation_fence(),
                now_ms()?,
            );
    assert_eq!(
        super::journal_availability::retained_setup_records(f)?,
        before
    );
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    assert_eq!(external_count(&f.f.path)?, effects);
    assert_eq!(
        (
            matches!(
                report_result,
                Err(AdmissionOperationStoreError::RecoveryAuthorityDenied)
            ),
            matches!(
                probe_result,
                Err(AdmissionOperationStoreError::RecoveryAuthorityDenied)
            ),
        ),
        (true, true),
        "caller-invalid proof bodies must remain authority refusals with healthy retained custody",
    );
    Ok(())
}
