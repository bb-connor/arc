//! Exit classes match `chio proof verify` and depend on the registry code
//! alone.

mod support;

use chio_bundle_verify::{
    exit_class_for_urn, verify_bundle, BundleVerifyError, BundleVerifyErrorKind, ExitClass,
};
use chio_core_types::crypto::Keypair;
use chio_core_types::root_authority::ReportColumn;
use chio_test_support::prelude::*;
use support::*;

const KINDS: &[(BundleVerifyErrorKind, ExitClass)] = &[
    (BundleVerifyErrorKind::Io, ExitClass::Unclassified),
    (BundleVerifyErrorKind::EnvelopeInvalid, ExitClass::Integrity),
    (
        BundleVerifyErrorKind::FileHashMismatch,
        ExitClass::Integrity,
    ),
    (
        BundleVerifyErrorKind::SignatureInvalid,
        ExitClass::Integrity,
    ),
    (
        BundleVerifyErrorKind::EvidenceInconsistent,
        ExitClass::Integrity,
    ),
    (
        BundleVerifyErrorKind::SchemaInvalid,
        ExitClass::ParseOrSchema,
    ),
    (
        BundleVerifyErrorKind::TrustInvalid,
        ExitClass::VerifierContext,
    ),
    (
        BundleVerifyErrorKind::TrustMissing,
        ExitClass::VerifierContext,
    ),
    (
        BundleVerifyErrorKind::FeatureUnsupported,
        ExitClass::VerifierContext,
    ),
    (
        BundleVerifyErrorKind::RequiredColumnUnverified,
        ExitClass::RequiredColumn,
    ),
];

#[test]
fn every_bundle_error_has_its_exit_class() {
    for (kind, class) in KINDS {
        let error = BundleVerifyError::new(*kind, "fixture");
        assert_eq!(error.exit_class(), *class, "{kind:?}");
        if *kind != BundleVerifyErrorKind::Io {
            let urn = error.code_urn().test_unwrap();
            assert!(urn.starts_with("urn:chio:error:attest:bundle-"), "{urn}");
            assert_eq!(exit_class_for_urn(urn), *class, "{urn}");
            assert_ne!(*class, ExitClass::Unclassified, "{kind:?}");
        }
    }
    assert_eq!(
        exit_class_for_urn("urn:chio:error:attest:signed-json-invalid-input"),
        ExitClass::ParseOrSchema
    );
    assert_eq!(
        exit_class_for_urn("urn:chio:error:attest:provenance-missing"),
        ExitClass::Unclassified
    );
}

#[test]
fn exit_codes_are_the_proof_verify_numbers() {
    let codes: Vec<i32> = [
        ExitClass::Verified,
        ExitClass::Unclassified,
        ExitClass::Usage,
        ExitClass::RequiredColumn,
        ExitClass::Integrity,
        ExitClass::ParseOrSchema,
        ExitClass::NegativeCaseMismatch,
        ExitClass::VerifierContext,
    ]
    .iter()
    .map(|class| class.code())
    .collect();
    assert_eq!(codes, vec![0, 1, 2, 10, 20, 30, 40, 50]);
}

#[test]
fn integrity_beats_required_column() {
    let directory = tempfile::tempdir().test_unwrap();
    write(directory.path(), &sample_bundle(), &package_keypair());
    std::fs::write(directory.path().join("receipts.ndjson"), b"\n").test_unwrap();
    let mut trust = package_trust();
    trust.required_columns = vec![ReportColumn::DelegationChain];
    let error = verify_bundle(directory.path(), &trust, None).test_unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::Integrity);
}

#[test]
fn parse_failure_stops_before_columns() {
    let directory = tempfile::tempdir().test_unwrap();
    write(directory.path(), &sample_bundle(), &package_keypair());
    std::fs::write(directory.path().join("manifest.json"), b"{not json").test_unwrap();
    let error = verify_bundle(directory.path(), &package_trust(), None).test_unwrap_err();
    assert_eq!(error.exit_class(), ExitClass::ParseOrSchema);
}

#[test]
fn unpinned_kernel_key_is_verifier_context() {
    let directory = tempfile::tempdir().test_unwrap();
    write(directory.path(), &sample_bundle(), &package_keypair());
    let trust = trust_for(vec![Keypair::generate().public_key()]);
    let error = verify_bundle(directory.path(), &trust, None).test_unwrap_err();
    assert_eq!(error.kind(), BundleVerifyErrorKind::TrustMissing);
    assert_eq!(error.exit_class(), ExitClass::VerifierContext);
}
