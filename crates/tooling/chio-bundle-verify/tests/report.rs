//! The column report of a verified bundle and its exit class.

mod support;

use chio_bundle_verify::{verify_bundle, EvidenceClass, ExitClass, BUNDLE_VERIFY_REPORT_SCHEMA};
use chio_core_types::root_authority::ReportColumn;
use chio_test_support::prelude::*;
use support::*;

fn bundle_dir() -> tempfile::TempDir {
    let directory = tempfile::tempdir().test_unwrap();
    write(directory.path(), &sample_bundle(), &package_keypair());
    directory
}

#[test]
fn decision_column_verifies_under_a_pinned_kernel_key() {
    let directory = bundle_dir();
    let mut trust = package_trust();
    trust.required_columns = vec![ReportColumn::Decision];
    let report = verify_bundle(directory.path(), &trust, None).test_unwrap();
    assert_eq!(report.schema, BUNDLE_VERIFY_REPORT_SCHEMA);
    assert_eq!(report.receipts.len(), 1);
    let columns = &report.receipts[0].columns;
    assert_eq!(columns.decision.class, EvidenceClass::Verified);
    assert_eq!(columns.identity_root.class, EvidenceClass::Unverifiable);
    assert_eq!(columns.content.class, EvidenceClass::Unverifiable);
    assert_eq!(report.exit_class(&trust), ExitClass::Verified);
    assert_eq!(report.exit_class, 0);
}

#[test]
fn unverified_required_column_exits_ten() {
    let directory = bundle_dir();
    let mut trust = package_trust();
    trust.required_columns = vec![ReportColumn::Decision, ReportColumn::DelegationChain];
    let report = verify_bundle(directory.path(), &trust, None).test_unwrap();
    assert_eq!(report.exit_class(&trust), ExitClass::RequiredColumn);
    assert_eq!(report.exit_class, 10);
}

#[test]
fn settlement_requirement_is_unsupported() {
    let directory = bundle_dir();
    let mut trust = package_trust();
    trust.required_columns = vec![ReportColumn::Settlement];
    let error = verify_bundle(directory.path(), &trust, None).test_unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::VerifierContext);
}

#[test]
fn report_rejects_unknown_members() {
    let directory = bundle_dir();
    let report = verify_bundle(directory.path(), &package_trust(), None).test_unwrap();
    let mut value = serde_json::to_value(&report).test_unwrap();
    value["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<chio_bundle_verify::VerificationReport>(value).is_err());
}

#[test]
fn observation_receipts_do_not_satisfy_a_required_decision_column() {
    use chio_core_types::receipt::body::ChioReceipt;
    use chio_core_types::receipt::evidence::EvidenceUncheckpointedReceipt;
    use chio_core_types::receipt::kinds::{
        BoundaryClass, ObservationOutcome, ReceiptKind, ToolOrigin, TrustLevel,
    };

    let directory = tempfile::tempdir().test_unwrap();
    let mut bundle = sample_bundle();
    let mut body = bundle.tool_receipts[0].receipt.body();
    body.decision = None;
    body.receipt_kind = ReceiptKind::AdvisoryEvaluation;
    body.boundary_class = BoundaryClass::AdvisoryOnly;
    body.observation_outcome = Some(ObservationOutcome::Observed);
    body.trust_level = TrustLevel::Advisory;
    body.tool_origin = ToolOrigin::HostExecutedUnmediated;
    bundle.tool_receipts[0].receipt = ChioReceipt::sign(body, &package_keypair()).test_unwrap();
    bundle.checkpoints.clear();
    bundle.inclusion_proofs.clear();
    bundle.uncheckpointed_receipts = vec![EvidenceUncheckpointedReceipt {
        seq: 1,
        receipt_id: bundle.tool_receipts[0].receipt.id.clone(),
    }];
    write(directory.path(), &bundle, &package_keypair());

    let mut trust = package_trust();
    trust.required_columns = vec![ReportColumn::Decision];
    let report = verify_bundle(directory.path(), &trust, None).test_unwrap();
    assert_eq!(
        report.receipts[0].columns.decision.class,
        EvidenceClass::Observed
    );
    assert_eq!(report.exit_class(&trust), ExitClass::RequiredColumn);
}
